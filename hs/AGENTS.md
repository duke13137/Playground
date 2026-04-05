# Haskell Project Guide

## Build & Development

- This project uses `Makefile`,`.ghci` and `~/.ghci`
- Watch `ghcid.txt` for compile errors and test failures
- DO NOT make or cabal unless being asked
- Search `ghci -e ':browse! Prelude'` before import extra modules
- Search `ghc -e ':hoogle <name>|<type>` to explore extra modules

## Debugging

- Use `tmux` skill to interact ghci debug pane
- Use `nvim_mcp` to sync nvim cursor to ghci breakpoint lines
- **Trace Threads**: Use `Debug.Breakpoint` (`breakpointM`) or `traceM` inside Wai handlers, as standard `:break` only works on the main thread.
- **Sync Editor + REPL**: Use `nvim_mcp` to jump the cursor to the current ghci breakpoint Debug.Breakpoint line
- **Ground State**: Run `psql` queries between debug steps to verify the database state matches application logic.
- **Interpreted Mode**: Load modules with the `*` prefix (e.g., `:load *src/Test.hs`) to ensure local variable info is available.
- **Force Thunks**: Use `:force <expr>` in GHCi to evaluate and see actual values of records and lazy data.
- **File Paths for Types**: Use absolute or relative file paths (e.g., `:type-at src/Main.hs ...`) for GHC 9.12+ type-at commands.
- **Permanent Debug Code**: DON'T delete `breakpointM` calls when finished; comment them out so they can be easily reused.
- **Compiled Debugging**: DON'T debug without the `*` prefix in `:load` or `:add`, or you'll lose access to local symbols.
