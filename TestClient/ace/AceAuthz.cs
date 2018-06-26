using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.CoAP.Util;
using Com.AugustCellars.COSE;
using Com.AugustCellars.WebToken;
using PeterO.Cbor;
using Oauth = Com.AugustCellars.CoAP.OAuth;

namespace TestClient
{
    class AceAuthz
    {
        class AuthServerInfo
        {
            public string AsName { get; }
            public string KeyName { get; }
            public CoapClient ClientLink { get; set; }
            public bool UseDTLS { get; set; } = false;
            public OneKey TlsKey { get; set; }
            public string Profile { get; }

            public AuthServerInfo(string[] cmd)
            {
                AsName = cmd[1];
                Profile = cmd[2];
                KeyName = cmd[3];

                switch (Profile.ToLower()) {
                    case "dtls":
                    case "coap_dtls":
                        UseDTLS = true;
                        break;

                    default:
                        Console.WriteLine("Unknown profile {0}", Profile);
                        break;
                }

                if (Program._TlsKeys.ContainsKey(KeyName)) {
                    TlsKey = Program._TlsKeys[KeyName];
                }
                else {
                    Console.WriteLine("Can't find TLS key {0}", KeyName);
                }
           }

            public void Print()
            {
                Console.WriteLine($"Name='{AsName}'   Use Key='{KeyName}'");
            }

        }


        private static Dictionary<string, AuthServerInfo> authServers = new Dictionary<string, AuthServerInfo>();
        private Oauth.ProfileIds Profile { get; set; } = Oauth.ProfileIds.Coap_Dtls;

        public void Process(Request request, Response response)
        {
            //  Is this processable?
            if (response.StatusCode != StatusCode.Unauthorized ||
                response.ContentFormat != 65008) {
                return;
            }

            try {
                //  Init from the response data
                Oauth.AsInfo info = new Oauth.AsInfo(response.Payload);

                //  Missage this as needed.
                string aSServer = info.ASServer;

                //  Need to build one from scratch

                if (!authServers.ContainsKey(info.ASServer)) {
                    Console.WriteLine($"No security association is setup for {info.ASServer}");
                    return;
                }

                AuthServerInfo asi = authServers[info.ASServer];

                if (asi.ClientLink == null) {
                    asi.ClientLink = new CoapClient(new Uri(info.ASServer));
                    if (asi.UseDTLS) {
                        asi.ClientLink.EndPoint = new DTLSClientEndPoint(asi.TlsKey);
                        asi.ClientLink.EndPoint.Start();
                    }

                }

                // M00BUG - need to make sure that this will pickup a port number if given.
                string audience = $"{request.URI.Scheme}://{request.URI.Authority}";

                Oauth.Request myRequest = new Oauth.Request("client_credentials") {
                    Audience = audience,
                    Scope = CBORObject.FromObject( request.UriPath)                    
                };

                myRequest.Profile = Profile;

                byte[] payload = myRequest.EncodeToBytes();

                asi.ClientLink.Timeout = 2 * 60 * 1000;
                Response asResponse = asi.ClientLink.Post(payload, MediaType.ApplicationCbor);


                if (asResponse == null) {
                    asi.ClientLink.EndPoint.Stop();
                    asi.ClientLink = null;
                    Console.WriteLine($"Timed out requesting token from {info.ASServer}");
                    return;
                }

                if (asResponse.StatusCode != StatusCode.Created) {
                    //  We had an error condition appear
                    if (asResponse.Payload != null) {
                        CBORObject obj = CBORObject.DecodeFromBytes(asResponse.Payload);
                        int error = obj["error"].AsInt32();
                        string errorText = "";
                        if (obj.ContainsKey("error_description")) errorText = obj["error_description"].AsString();
                        Console.WriteLine(
                            $"Recieved an error {asResponse.StatusCode} with error no = {error} and description '{errorText}'");
                    }
                    else {
                        Console.WriteLine($"Received and error {asResponse.StatusCode} from the AS but no text");
                    }

                    return;
                }

                Oauth.Response myResponse = new Oauth.Response(asResponse.Payload);


                // default profile for client - 
#if false
                if (Profile != null && myResponse.Profile != Profile) {
                    Console.WriteLine("AS Server returned an unexpected profile {0}", myResponse.Profile);
                    return;
                }
#endif
                myResponse.Profile = Oauth.ProfileIds.Coap_Dtls;

                //  Post token to resource server

                CoapClient client = new CoapClient();
                client.Uri = new Uri($"coap://{request.URI.Authority}/authz-info");
                client.Timeout = 10000; // 1 second
                Response tknResponse = client.Post(myResponse.Token, MediaType.ApplicationCbor);
                if (tknResponse == null) {
                    Console.WriteLine("Post of token failed w/ no response");
                    return;
                }

                if (tknResponse.StatusCode != StatusCode.Created) {
                    Console.WriteLine($"Post of token failed with error {tknResponse.StatusCode}");
                    return;
                }

                Confirmation cnf = myResponse.Confirmation;


                Request newRequest = new Request(request.Method);
                newRequest.Payload = request.Payload;
                newRequest.SetOptions(request.GetOptions());

                DTLSClientEndPoint endPoint = null;

                switch (myResponse.Profile) {
                case Oauth.ProfileIds.Coap_Dtls: {
                    OneKey key = cnf.Key;
                    endPoint = new DTLSClientEndPoint(cnf.Key);
                    endPoint.Start();

                    newRequest.EndPoint = endPoint;
                    newRequest.URI = new Uri($"coaps://{request.URI.Authority}/{request.URI.AbsolutePath}");
                }
                    break;

                case Oauth.ProfileIds.Coap_Oscore: {
                    OneKey oneKey = cnf.Key;
                    byte[] salt = null;
                    if (oneKey.ContainsName("slt")) salt = oneKey[CBORObject.FromObject("slt")].GetByteString();
                    CBORObject alg = null;
                    if (oneKey.ContainsName(CoseKeyKeys.Algorithm)) alg = oneKey[CoseKeyKeys.Algorithm];
                    CBORObject kdf = null;
                    if (oneKey.ContainsName(CBORObject.FromObject("kdf"))) kdf = oneKey[CBORObject.FromObject("kdf")];

                    SecurityContext oscoapContext = SecurityContext.DeriveContext(
                        oneKey[CoseKeyParameterKeys.Octet_k].GetByteString(),
                        oneKey[CBORObject.FromObject("sid")].GetByteString(),
                        oneKey[CBORObject.FromObject("rid")].GetByteString(),
                        salt, alg, kdf);
                    newRequest.OscoapContext = oscoapContext;
                }
                    break;

                default:
                    Console.WriteLine("Cannot rewrite as we don't recognize the profile");
                    return;

                }

                newRequest.Respond += delegate (Object sender, ResponseEventArgs e)
                {
                    Response responseN = e.Response;
                    if (responseN == null) {
                        Console.WriteLine("Request timeout");
                    }
                    else {
                        Console.WriteLine(Utils.ToString(responseN));
                        Console.WriteLine("Time (ms): " + responseN.RTT);
                    }

                    if (endPoint != null) {
                        endPoint.Stop();
                    }
                };

                newRequest.Send();
            }
            catch (Exception e) {
                Console.WriteLine("Error processing AceAuthz - " + e.ToString());
            }
        }

        public static void AddCommands(DispatchTable table)
        {
            table.Add("as_add", new Dispatch("Set parameters for a 'new' Authorization Server", "as_add_server <serverurl> <profile> <user key>", AddAuthServer));
            table.Add("as_list", new Dispatch("List active Authroization servers", "as_list", ListAuthServers));
            table.Add("as_use_profile", new Dispatch("Set the profile to use with the resource server", "as_use_profile <profile name>", SetProfile));
            table.Add("as_test", new Dispatch("RUn Dispatch Tests", "as_test <number>", AceTest.Test));
        }


        public static void AddAuthServer(string[] cmds)
        {
            if (cmds.Length != 4) {
                Console.WriteLine("Incorrect number of arguments");
                return;
            }
            else {
                authServers.Add(cmds[1], new AuthServerInfo(cmds));
            }
        }

        public static void ListAuthServers(string[] cmds)
        {
            foreach (AuthServerInfo x in authServers.Values) {
                x.Print();
            }
        }

        public static void SetProfile(string[] cmds)
        {
            if (cmds.Length != 2) {
                Console.WriteLine("Incorrect number of arguments");
            }
            else {
                switch (cmds[1]) {
                    case "coap_dtls":
                        Program.AceAuthzHandler.Profile = Oauth.ProfileIds.Coap_Dtls;
                        break;

                    case "coap_oscore":
                        Program.AceAuthzHandler.Profile = Oauth.ProfileIds.Coap_Oscore;
                        break;

                    default:
                        Console.WriteLine("Unknown profile type set");
                        break;
                }
            }
        }

    }

}
