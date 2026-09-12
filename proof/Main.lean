import AgentGuard

open Lean AgentGuard

def main : IO Unit := do
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  let line ← stdin.getLine
  let parsed := Json.parse line >>= fromJson? (α := Query)
  match parsed with
  | .error e => throw (IO.userError e)
  | .ok q =>
    let result := Json.mkObj [("allow", toJson (allowed q)), ("nextLabels", toJson (nextLabels q))]
    stdout.putStrLn result.compress
