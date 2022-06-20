# LEOPARDSEAL
LEOPARDSEAL is a simple Linux in-memory .so loader created for practicing techniques described in https://tishina.in/execution/linux-evasion-primitives and maybe even some real-world usage.

Currently, when preloading itself, it runs two copies, which I consider a good thing. You can tamper with the function used to start the process to change this behaviour.

I use `sliver> generate -o linux -f shared --run-at-load` to create end payloads for this. 
# usage
`LEOPARDSEAL` is written to be used to create several loader stages, either with run-at-load chaining or with signaling:
![lseal_signals](https://user-images.githubusercontent.com/502153/174596860-f12e6138-e67e-44de-9ade-0e9e1f5f3ccc.PNG)
![lseal_nnosignals](https://user-images.githubusercontent.com/502153/174596871-38c34f72-0220-4098-b2e7-bdaa7d114436.PNG)

The amount of features is by no means staggering:
```
 LEOPARDSEAL: a linux loader without an ASCII banner

usage: build.py [-h] [-o OUTPUT] [-p PROCESSNAME] [-f PREFORKS] [--signal] [--wait] [--shared] [--forever] [-s SO]

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        output
  -p PROCESSNAME, --processname PROCESSNAME
                        process to preload to
  -f PREFORKS, --preforks PREFORKS
                        prefork count
  --signal              send a SIGINT to the child process
  --wait                wait for SIGINT before running (only for shared libraries)
  --shared              generate an .so file
  --forever             run forever

required arguments:
  -s SO, --so SO        path to the .SO library
```

The loader is quite unstable at the moment, but it's nothing a quick 15-minute debugging session won't fix ;)
