package backup

// containercontrol.go — the data model behind the Container Control page:
// every real container on the host, grouped by each container's own
// `depends_on:` relationships within its compose project — read straight
// off Docker Compose's own com.docker.compose.depends_on label, the same
// label ComposeDependencies (discover.go) already reads, just batched here
// instead of one `docker inspect` per container.
//
// Why depends_on instead of Docker Compose's "project" label: a typical
// homelab setup (this one included) runs its ENTIRE stack as one
// docker-compose.yml, so com.docker.compose.project is the SAME value for
// every single container — grouping by project alone would just produce
// one giant flat list, no better than no grouping at all.
//
// Why depends_on instead of container-name prefixes ("immich_" naming):
// name-prefix matching is what the Backups page and Applications already
// do (app.ID substring matching), and it's exactly what silently failed
// for e.g. "immich_postgres" — its compose SERVICE name is "database", not
// "immich-anything", so no naming heuristic would ever catch it. What DOES
// know they belong together is the compose file itself: immich-server
// declares `depends_on: [redis, database]`, and Compose stamps that
// directly onto the immich-server container as a label. Reading that label
// is the one mechanism that's actually driven by the user's real compose
// file rather than a guess about naming conventions.
//
// A container that's the target of more than one other container's
// depends_on stays with whichever claims it first, in alphabetical order by
// the claiming container's name — deterministic, and multi-parent
// dependencies are rare enough in practice that any consistent tie-break
// beats a random one. Dependency chains are resolved transitively (A
// depends_on B depends_on C all end up in one group), not just one level
// deep.

import (
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
)

// ContainerControlItem is one real container, enriched for the Container
// Control UI. Image/State/Health/ExitCode mirror ContainerInfo's fields
// (kept separate rather than embedding ContainerInfo since this needs
// Service/Project too, which ContainerInfo deliberately doesn't carry —
// see ContainerInfo's own doc comment for why it stays minimal).
type ContainerControlItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Service  string `json:"service,omitempty"` // com.docker.compose.service label — "" if not compose-managed
	Project  string `json:"project,omitempty"` // com.docker.compose.project label
	Image    string `json:"image"`
	State    string `json:"state"`
	Health   string `json:"health,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
}

// ContainerControlGroup is one or more containers shown together — either a
// depends_on-linked set anchored on the container that nothing else claims
// as a dependency, or a lone standalone container (no compose relationships
// at all, including plain `docker run` containers with no compose labels).
type ContainerControlGroup struct {
	Anchor     string                  `json:"anchor"` // display name — the anchor container's name
	Containers []ContainerControlItem  `json:"containers"`
}

type inspectLabelsEntry struct {
	ID     string `json:"Id"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

// batchInspectLabels fetches every ID's labels in ONE `docker inspect`
// call, not one per container — the same "one snapshot, not N subprocess
// spawns" principle dockerPsSnapshot already applies to `docker ps`. Needed
// because docker ps's own --format .Labels output is a single comma-joined
// string across ALL of a container's labels, which is genuinely ambiguous
// to parse back apart when a label's own VALUE also contains commas —
// exactly what com.docker.compose.depends_on's value does for any
// container with more than one dependency (e.g.
// "redis:service_started:true,database:service_started:true" is
// indistinguishable, after a naive comma-split, from two separate labels).
// `docker inspect`'s JSON output has no such ambiguity.
func batchInspectLabels(ids []string) map[string]map[string]string {
	if len(ids) == 0 {
		return nil
	}
	args := append([]string{"inspect"}, ids...)
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		return nil
	}
	var entries []inspectLabelsEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil
	}
	result := make(map[string]map[string]string, len(entries))
	for _, e := range entries {
		result[e.ID] = e.Config.Labels
	}
	return result
}

// ListContainerControlGroups returns every container on the host (running
// or stopped), grouped by depends_on relationships within each compose
// project. Containers with no compose labels at all (plain `docker run`,
// not part of any docker-compose.yml) each get their own single-container
// group too — every container on the host is represented here, not just
// ones tied to a registered PrestoBack app.
func ListContainerControlGroups() ([]ContainerControlGroup, error) {
	snapshot, err := dockerPsSnapshot()
	if err != nil {
		return nil, err
	}

	ids := make([]string, len(snapshot))
	for i, e := range snapshot {
		ids[i] = e.ID
	}
	labelsByID := batchInspectLabels(ids)

	type node struct {
		item              ContainerControlItem
		dependsOnServices []string
	}
	nodes := make(map[string]*node, len(snapshot))
	byProjectService := map[string]string{} // "project|service" -> containerID

	for _, e := range snapshot {
		labels := labelsByID[e.ID]
		project := labels[composeProjectLabel]
		service := labels[composeServiceLabel]
		health, exitCode := HealthAndExitFromStatus(e.Status)

		n := &node{item: ContainerControlItem{
			ID: e.ID, Name: e.Name, Service: service, Project: project,
			Image: e.Image, State: e.State, Health: health, ExitCode: exitCode,
		}}
		if depsRaw := labels[composeDependsOnLabel]; depsRaw != "" {
			// Format is "service:condition:required[,service2:condition:required]"
			// — same defensive first-field-only parse ComposeDependencies uses.
			for _, entry := range strings.Split(depsRaw, ",") {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				svc := strings.SplitN(entry, ":", 2)[0]
				if svc != "" {
					n.dependsOnServices = append(n.dependsOnServices, svc)
				}
			}
		}
		nodes[e.ID] = n
		if project != "" && service != "" {
			byProjectService[project+"|"+service] = e.ID
		}
	}

	// Deterministic processing order for the tie-break rule described above.
	orderedIDs := make([]string, 0, len(nodes))
	for id := range nodes {
		orderedIDs = append(orderedIDs, id)
	}
	sort.Slice(orderedIDs, func(i, j int) bool { return nodes[orderedIDs[i]].item.Name < nodes[orderedIDs[j]].item.Name })

	// Resolve each container's depends_on service names to actual sibling
	// container IDs within the same project, and record who "claims" each
	// dependency first.
	claimedBy := map[string]string{} // dependency containerID -> claiming parent containerID
	for _, id := range orderedIDs {
		n := nodes[id]
		for _, svc := range n.dependsOnServices {
			depID, ok := byProjectService[n.item.Project+"|"+svc]
			if !ok || depID == id {
				continue
			}
			if _, already := claimedBy[depID]; !already {
				claimedBy[depID] = id
			}
		}
	}
	childrenOf := map[string][]string{}
	for depID, parentID := range claimedBy {
		childrenOf[parentID] = append(childrenOf[parentID], depID)
	}

	var groups []ContainerControlGroup
	for _, id := range orderedIDs {
		if _, isClaimed := claimedBy[id]; isClaimed {
			continue // included under its claiming parent's group below
		}
		collected := collectGroup(id, childrenOf)
		sort.Slice(collected, func(i, j int) bool {
			if collected[i] == id {
				return true
			}
			if collected[j] == id {
				return false
			}
			return nodes[collected[i]].item.Name < nodes[collected[j]].item.Name
		})
		g := ContainerControlGroup{Anchor: nodes[id].item.Name}
		for _, cid := range collected {
			g.Containers = append(g.Containers, nodes[cid].item)
		}
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Anchor < groups[j].Anchor })
	return groups, nil
}

// collectGroup walks childrenOf breadth-first from root, resolving
// transitive dependency chains (A depends_on B depends_on C) into one flat
// group rather than only catching direct dependencies.
func collectGroup(root string, childrenOf map[string][]string) []string {
	seen := map[string]bool{root: true}
	queue := []string{root}
	var collected []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		collected = append(collected, cur)
		for _, child := range childrenOf[cur] {
			if !seen[child] {
				seen[child] = true
				queue = append(queue, child)
			}
		}
	}
	return collected
}
