import Lake
open Lake DSL

package «sovereign_lattice»

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.34.0-rc2"

@[default_target]
lean_lib «GodelLobBFT»
