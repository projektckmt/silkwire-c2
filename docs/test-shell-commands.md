# Testing Shell Command Execution

## How to Test

1. **Start the server** (in terminal 1):
   ```bash
   cd certs && ../bin/c2-server
   ```

2. **Start the client** (in terminal 2):
   ```bash
   ./bin/c2-client localhost:8443
   ```
   
   Watch this terminal for debug output showing exactly what commands are being executed.

3. **Use the console** (in terminal 3):
   ```bash
   ./bin/c2-console localhost:8443
   c2> sessions
   c2> session cd334a25
   (hostname) > shell echo "Hello World"
   (hostname) > shell pwd
   (hostname) > shell ls -la
   (hostname) > pwd
   (hostname) > ls
   (hostname) > back
   c2> exit
   ```

## Expected Behavior

With the debug logging, you should see in the **client terminal**:
```
Executing command: Type=SHELL, Command='echo Hello World', Args=[]
executeShell: command='echo Hello World', args=[]
Linux: executing 'sh -c echo Hello World'
Command result: output='Hello World
', error=<nil>
Command executed successfully, output length: 12 bytes
```

And in the **server terminal**:
```
Task result from cd334a25...: Hello World
```

## Common Issues

1. **If you see `Args=[echo Hello World]`** - This means the console fix didn't work properly
2. **If commands still fail** - Check the debug output to see exactly what's being executed
3. **If no debug output** - The command isn't reaching the client

## Test Commands That Should Work

```bash
(hostname) > shell echo "test"          # Should output: test
(hostname) > shell pwd                  # Should show current directory  
(hostname) > shell whoami              # Should show username
(hostname) > shell date                # Should show current date
(hostname) > pwd                       # Should work (built-in command)
(hostname) > ps                        # Should list processes
```