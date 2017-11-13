# TestClient - Scripted CoAP test client

[![Build Status](https://api.travis-ci.org/Com-AugustCellars/TestClient.png)](https://travis-ci.org/jimsch/TestClient)

The Constrained Application Protocol (CoAP) (https://datatracker.ietf.org/doc/draft-ietf-core-coap/)
is a RESTful web transfer protocol for resource-constrained networks and nodes.

TestClient provides for a script based method of doing simple testing of the different features of a CoAP based REST interface.  This can be augmented by creating code based tests which can be run with a single command.

Reviews and suggestions would be appreciated.

## Copyright

Copyright (c) 2017, Jim Schaad <ietf@augustcellars.com>

## Building the sources

I am currently sync-ed up to Visual Studio 2017 and have started using language features of C# v7.0 that are supported both in Visual Studio and in the latest version of mono.

## Writing Scripts

A script consists of a text file with one command per line.  All commands are case insensitive as are most arguments for commands.  Commands which create CoAP messages are generally performed asynchronusly, and thus a liberal sprinkling of sleep commands can help trying to figure out what happens which a script is running.  All state created while a script is running is retained when the script finishes.

## Commands

This summary is probably going to be incomplete.  With any luck the internal help will be more complete.  The syntax of a command is <command> <argument list>.

### CoAP Methods:

<method> <uri or partial uri> <payload>

methods are: GET, PUT, DELETE, POST, FETCH, PATCH, iPATCH
psudeo-methods are: OBSERVE, UNOBSERVE, DISCOVER

uri or parital uri: the URI to send the command to.  Parital URIs will be resolved relative to the internal HOST parameter.

payload: Currently is a text value.  Multiple words may be enclosed in double quotes.

DISCOVER does not automatically use the partial uri of /.well-known/core.

### State Commands:

This commands will modify the internal state.  Anything in the state will be added to any coap request that is created and sent.

CLEAR-OPTION <option name> - Remove all instances of option from the state
HOST <uri> - Resolve all relative URIs to with this URI.  Defaults to the empty string.
OPTION <option name> <list of values> - 
SET-ENDPOINT < TCP | UDP > - Use a TCP or a UDP endpoint for sending the commands.  Defaults to UDP on start.

### Keying

ADD-OSCOAP <key name> <CBOR object> - Create an OSCOAP key with the given name
ADD-OSCOAP-GROUP <group name> <cbor object> - Create an OSCOAP group context with the given name
USE-OSCOAP <key name> - Use a OSCOAP context on the message.  The name NONE is reserved to remove the key.
OSCOAP-PIV <n> -

ADD-TLSKEY <key name> <COSE Key> - Add the key to the set of TLS keys and given it <key name>.
USE-TLSKEY <key name> - Use a TLS/DTLS version of the end point with this key.  Currently only symmetric keys are supported.



### Other Commands:

COMMENT <text> - No command executed.  Text is not echoed.
EXIT - quit the program.  Using EXIT in a script will cause the program not the script to exit.
HELP - print a summary of the commands
LOG-LEVEL <NONE | INFO | FATAL> - control the level of logging produced by the system.  Defaults to NONE.
PAUSE - Stop script execution until a <return> is entered on the console.
SCRIPT <filename> - run the commands in a script
SLEEP <n> - sleeps for n seconds

### Test Suites:

EDHOC - Runs a set of EDHOC commands to test that protocol.
OSCOAP-TEST <n> - Run test number n from the OSCOAP test suite.


## License

See [LICENSE](LICENSE) for more info.

