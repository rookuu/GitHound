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

## Usage Examples

## Contributing

We welcome and appreciate your contributions! To make the process smooth and efficient, please follow these steps:

1. **Discuss Your Idea**  
   - If you’ve found a bug or want to propose a new feature, please start by opening an issue in this repo. Describe the problem or enhancement clearly so we can discuss the best approach.

2. **Fork & Create a Branch**  
   - Fork this repository to your own account.  
   - Create a topic branch for your work:
     ```bash
     git checkout -b feat/my-new-feature
     ```

3. **Implement & Test**  
   - Follow the existing style and patterns in the repo.  
   - Add or update any tests/examples to cover your changes.  
   - Verify your code runs as expected:
     ```bash
     # e.g. dot-source the collector and run it, or load the model.json in BloodHound
     ```

4. **Submit a Pull Request**  
   - Push your branch to your fork:
     ```bash
     git push origin feat/my-new-feature
     ```  
   - Open a Pull Request against the `main` branch of this repository.  
   - In your PR description, please include:
     - **What** you’ve changed and **why**.  
     - **How** to reproduce/test your changes.

5. **Review & Merge**  
   - I’ll review your PR, give feedback if needed, and merge once everything checks out.  
   - For larger or more complex changes, review may take a little longer—thanks in advance for your patience!

Thank you for helping improve this extension! 🎉  

## Licensing

```
Copyright 2025 Jared Atkinson

Licensed under the Apache License, Version 2.0
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Unless otherwise annotated by a lower-level LICENSE file or license header, all files in this repository are released
under the `Apache-2.0` license. A full copy of the license may be found in the top-level [LICENSE](LICENSE) file.
