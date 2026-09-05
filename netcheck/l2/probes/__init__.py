"""Active layer 2 checks.

No check transmits directly. Each is handed a context and can only ask it to
send, which is where the budgets, the send rate and the abort watcher live.
"""
