# GitHound

## Overview

## Collector Setup & Usage

## Schema

### Nodes

Nodes correspond to each object type.

| Node             | Description                                               | Image                                                                    | Icon        | Color |
|------------------|-----------------------------------------------------------|--------------------------------------------------------------------------|-------------|-------|
| `GHOrganization` |                                                           | <img src="./images/white_GHOrganization.svg" width="30" class="center"/> | building    | #5FED83 |
| `GHUser`         |                                                           | <img src="./images/white_GHUser.svg" width="30" class="center"/>         | user        | #FF8E40 |
| `GHTeam`         |                                                           | <img src="./images/white_GHTeam.svg" width="30" class="center"/>         | user-group  | #C06EFF |
| `GHRepository`   |                                                           | <img src="./images/white_GHRepository.svg" width="30" class="center"/>   | box-archive | #9EECFF |
| `GHBranch`       |                                                           | <img src="./images/white_GHBranch.svg" width="30" class="center"/>       | code-branch | #FF80D2 |
| `GHOrgRole`      |                                                           | <img src="./images/white_GHOrgRole.svg" width="30" class="center"/>      | user-tie    | #BFFFD1 |
| `GHTeamRole`     |                                                           | <img src="./images/white_GHTeamRole.svg" width="30" class="center"/>     | user-tie    | #D0B0FF |
| `GHRepoRole`     |                                                           | <img src="./images/white_GHRepoRole.svg" width="30" class="center"/>     | user-tie    | #DEFEFA |

### Edges

Edges capture every relationship; who contaiins what, membership, read vs. write permissions, etc.

