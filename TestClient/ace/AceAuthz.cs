using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net.Configuration;
using System.Reflection;
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
            public string ClientKey { get; }
            public CoapClient ClientLink { get; set; }
            public bool UseDTLS { get; set; } = false;
            public OneKey TlsKey { get; set; }
            public SecurityContext OscoreKey { get; set; }
            public string Profile { get; }
            public bool UseJSON { get; set; }

            public AuthServerInfo(string[] cmd)
            {
                AsName = cmd[1];
                Profile = cmd[2];
                KeyName = cmd[3];
                if (cmd.Length > 4) {
                    int idx = 4;
                    if (cmd[idx].ToLower() == "json") {
                        UseJSON = true;
                        idx++;
                    }

                    if (idx < cmd.Length) {
                        ClientKey = cmd[idx];
                        idx++;
                    }

                    if (idx < cmd.Length) {
                        throw new Exception("Did not use all of the arguments.");
                    }
                }

                switch (Profile.ToLower()) {
                case "dtls":
                case "coap_dtls":
                    UseDTLS = true;
                    break;

                    case "coap_oscore":
                        UseDTLS = false;
                        break;

                default:
                    Console.WriteLine("Unknown profile {0}", Profile);
                    break;
                }

                if (UseDTLS) {
                    if (Program._TlsKeys.ContainsKey(KeyName)) {
                        TlsKey = Program._TlsKeys[KeyName].RawPublicKey;
                    }
                    else {
                        Console.WriteLine("Can't find TLS key {0}", KeyName);
                    }
                }
                else {
                    if (Program._OscopKeys.ContainsKey(KeyName)) {
                        OscoreKey = Program._OscopKeys[KeyName];
                    }
                    else {
                        Console.WriteLine($"Can't find the OSCORE key {KeyName}");
                    }
                }
            }

            public void Print()
            {
                Console.WriteLine($"Name='{AsName}'   Use Key='{KeyName}'");
            }
        }

        public class ResourceInfo
        {
            public OneKey Rpk { get; }

            public ResourceInfo(OneKey key)
            {
                Rpk = key;
            }

            public void CheckRPK(Object obj, TlsEvent e)
            {
                if (e.Code == TlsEvent.EventCode.ServerCertificate) {
                    e.Processed = Rpk.Compare(e.KeyValue);
                }
            }
        }


        private static Dictionary<string, AuthServerInfo> authServers = new Dictionary<string, AuthServerInfo>();
        private Oauth.ProfileIds Profile { get; set; } = Oauth.ProfileIds.Coap_Dtls;

        public void Process(Request request, Response response)
        {
            //  Is this processable?
            if (response.StatusCode != StatusCode.Unauthorized /* ||
                !(response.ContentFormat == 65008 || response.ContentFormat == MediaType.ApplicationCbor)*/) {
                return;
            }

            try {
                //  Init from the response data
                Oauth.AsInfo info = new Oauth.AsInfo(response.Payload);

                //  Massage this as needed.
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
                    else {
                        if (asi.ClientLink.Uri.Scheme == "coaps") {
                            asi.ClientLink.Uri = new Uri($"coap://{asi.ClientLink.Uri.Authority}/{asi.ClientLink.UriPath}");
                        }
                        asi.ClientLink.OscoapContext = asi.OscoreKey;
                    }
                }

                // M00BUG - need to make sure that this will pickup a port number if given.
                string audience = $"{request.URI.Scheme}://{request.URI.Authority}";
                if (UseAudience != null) {
                    audience = UseAudience;
                }

                Oauth.Request myRequest = new Oauth.Request("client_credentials") {
                    Audience = audience,
                    Scope = (UseScopeValue == null) ? CBORObject.FromObject(request.UriPath) : UseScopeValue
                };

                if (ClientKey != null) {
                    myRequest.Cnf = new Confirmation();
                    switch (ClientKeyType) {
                    case 1: // kid
                        myRequest.Cnf.Kid = ClientKey[CoseKeyKeys.KeyIdentifier].GetByteString();
                        break;

                    case 2: // key
                        myRequest.Cnf.Key = ClientKey;
                        break;
                    }
                }

                Response asResponse;
                if (asi.UseJSON) {
                    string jsonPayload = myRequest.EncodeToString();
                    asi.ClientLink.Timeout = 2 * 60 * 1000;
                    asResponse = asi.ClientLink.Post(jsonPayload, MediaType.ApplicationJson);
                }
                else {
                    byte[] payload = myRequest.EncodeToBytes();
                    asi.ClientLink.Timeout = 2 * 60 * 1000;
                    asResponse = asi.ClientLink.Post(payload, MediaType.ApplicationCbor);

                }


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
                        int error = obj[/*"error"*/ CBORObject.FromObject(15)].AsInt32();
                        string errorText = "";
                        if (obj.ContainsKey(/*"error_description")*/ CBORObject.FromObject(16))) errorText = obj[CBORObject.FromObject(16)].AsString();
                        Console.WriteLine(
                            $"Received an error {asResponse.StatusCode} with error no = {error} and description '{errorText}'");
                    }
                    else {
                        Console.WriteLine($"Received and error {asResponse.StatusCode} from the AS but no text");
                    }

                    return;
                }

                Oauth.Response myResponse =  Oauth.Response.FromCBOR(asResponse.Payload);


                // default profile for client - 
#if false
                if (Profile != null && myResponse.Profile != Profile) {
                    Console.WriteLine("AS Server returned an unexpected profile {0}", myResponse.Profile);
                    return;
                }
#endif
                if (!myResponse.ContainsKey(Oauth.Oauth_Parameter.Profile)) {
                    myResponse.Profile = Oauth.ProfileIds.Coap_Dtls;
                }

                //  Post token to resource server

                byte[][] OscoreSalts = null;

                if (!SendTokenAsPsk) {
                    CoapClient client = new CoapClient();
                    client.Uri = new Uri($"coap://{request.URI.Authority}/authz-info");
                    client.Timeout = 10000; // 1 second

                    Response tknResponse = null;
                    if (myResponse.Profile == Oauth.ProfileIds.Coap_Oscore) {
                        byte[] mySalt = new byte[] {32, 33, 34, 35, 36, 37, 38};
                        CBORObject post = CBORObject.NewMap();
                        post.Add((CBORObject) Oauth.Oauth_Parameter.Access_Token, myResponse.Token);
                        post.Add((CBORObject) Oauth.Oauth_Parameter.CNonce, mySalt);
                        tknResponse = client.Post(post.EncodeToBytes(), MediaType.ApplicationAceCbor);
                        OscoreSalts = new byte[][] {mySalt, null};
                    }
                    else {
                        tknResponse = client.Post(myResponse.Token, MediaType.ApplicationOctetStream);
                    }

                    if (tknResponse == null) {
                        Console.WriteLine("Post of token failed w/ no response");
                        return;
                    }

                    if (tknResponse.StatusCode != StatusCode.Created) {
                        Console.WriteLine($"Post of token failed with error {tknResponse.StatusCode}");
                        return;
                    }

                    if (tknResponse.ContentType == MediaType.ApplicationAceCbor) {
                        CBORObject post = CBORObject.DecodeFromBytes(tknResponse.Payload);
                        if (post.ContainsKey((CBORObject) Oauth.Oauth_Parameter.Client_id)) {
                            //  Retrieve
                        }

                        if (post.ContainsKey((CBORObject) Oauth.Oauth_Parameter.CNonce)) {
                            if (OscoreSalts == null) {
                                throw new Exception("Internal Error - salts");
                            }
                            OscoreSalts[1] = post[(CBORObject) Oauth.Oauth_Parameter.CNonce].GetByteString();
                        }
                    }
                }

                Confirmation cnf = myResponse.Confirmation;
                if (cnf == null) {
                    if (ClientKey == null) {
                        Console.WriteLine("Returned a token but I don't know what key I should be using");
                        return;
                    }
                    cnf = new Confirmation(ClientKey);
                }

                if (cnf.Kid != null) {
                    Console.WriteLine("Missing code - how do we map a kid to a real key?");
                    return;
                }

                Request newRequest = new Request(request.Method);
                newRequest.Payload = request.Payload;
                newRequest.SetOptions(request.GetOptions());

                DTLSClientEndPoint endPoint = null;

                switch (myResponse.Profile) {
                case Oauth.ProfileIds.Coap_Dtls: {
                    OneKey key = cnf.Key;
                    LastKeyFound = cnf.Key;
                    if (SendTokenAsPsk) {
                        cnf.Key.AsCBOR().Set(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(myResponse.Token));
                    }

                    endPoint = new DTLSClientEndPoint(cnf.Key);
                    endPoint.Start();

                    if (myResponse.RsConfirmation != null) {
                        ResourceInfo rsInfo = new ResourceInfo(myResponse.RsConfirmation.Key);
                        endPoint.TlsEventHandler += rsInfo.CheckRPK;
                    }

                    newRequest.EndPoint = endPoint;
                    newRequest.URI = new Uri($"coaps://{request.URI.Authority}/{request.URI.AbsolutePath}");
                }
                    break;

                case Oauth.ProfileIds.Coap_Oscore: {
                    CBORObject oscoreContext = cnf.AsCBOR[CBORObject.FromObject(Confirmation.ConfirmationIds.COSE_OSCORE)];

                    byte[] salt = null;
                    if (oscoreContext.ContainsKey(CBORObject.FromObject(6))) salt = oscoreContext[CBORObject.FromObject(CBORObject.FromObject(6))].GetByteString();
                    CBORObject alg = null;
                    if (oscoreContext.ContainsKey(CBORObject.FromObject(5))) alg = oscoreContext[CBORObject.FromObject(5)];
                    CBORObject kdf = null;
                    if (oscoreContext.ContainsKey(CBORObject.FromObject(4))) kdf = oscoreContext[CBORObject.FromObject(4)];
                    byte[] keyContext = null;
                    if (oscoreContext.ContainsKey(CBORObject.FromObject(7))) {
                        keyContext = oscoreContext[CBORObject.FromObject(7)].GetByteString();
                    }

                    if (OscoreSalts == null) {
                        throw new Exception("Internal Error");
                    }

                    keyContext = new byte[OscoreSalts[0].Length + OscoreSalts[1].Length];
                    Array.Copy(OscoreSalts[0], keyContext, OscoreSalts[0].Length);
                    Array.Copy(OscoreSalts[1], 0, keyContext, OscoreSalts[0].Length, OscoreSalts[1].Length);

                    SecurityContext oscoapContext = SecurityContext.DeriveContext(
                        oscoreContext[CBORObject.FromObject(1)].GetByteString(), keyContext,
                        oscoreContext[CBORObject.FromObject(2)].GetByteString(), 
                        oscoreContext[CBORObject.FromObject(3)].GetByteString(),
                        salt, alg, kdf);
                    oscoapContext.GroupId = null;  // HACK HACK HACK

                    newRequest.OscoapContext = oscoapContext;

                    newRequest.URI = new Uri($"coap://{request.URI.Authority}/{request.URI.AbsolutePath}");

                }
                    break;

                default:
                    Console.WriteLine("Cannot rewrite as we don't recognize the profile");
                    return;

                }

                newRequest.Respond += delegate(object sender, ResponseEventArgs e)
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
            table.Add("as_add",
                      new Dispatch("Set parameters for a 'new' Authorization Server",
                                   "as_add_server <serverurl> <profile> <user key> [JSON] [<server key>]", AddAuthServer));
            table.Add("as_list", new Dispatch("List active Authroization servers", "as_list", ListAuthServers));
            table.Add("as_use_profile",
                      new Dispatch("Set the profile to use with the resource server", "as_use_profile <profile name>",
                                   SetProfile));
            table.Add("as_test", new Dispatch("RUn Dispatch Tests", "as_test <number>", AceTest.Test));
            table.Add("as_psk", new Dispatch("Send the token as the PSK", "as_psk [yes|no]", SetPskUsage));
            table.Add("as_use_scope",
                      new Dispatch("Set the scope to be used", "as_use_scope h'XXXXX' or \"XXXXX\"", SetScope));
            table.Add("as_audience", new Dispatch("Set the audience value to use on request", "as_audience <string>", SetAudience));
            table.Add("as_user_key", new Dispatch("Set the user key to be sent as part of the AS request", "as_user_key <key name>", SetUserKey));
            table.Add("as_save_key", new Dispatch("Save the last key with a name", "as_save_key <key name>", SaveLastKey));
        }


        public static void AddAuthServer(string[] cmds)
        {
            if (cmds.Length < 4 || cmds.Length > 6) {
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

        private static bool SendTokenAsPsk = false;


        public static void SetPskUsage(string[] cmds)
        {
            if (cmds.Length != 2) {
                Console.WriteLine("Incorrect number of parameters");
                return;
            }

            switch (cmds[1].ToLower()) {
            case "yes":
                SendTokenAsPsk = true;
                break;

            case "no":
                SendTokenAsPsk = false;
                break;

            default:
                Console.WriteLine("Unrecognized option");
                break;
            }
        }

        private static CBORObject UseScopeValue = null;

        public static void SetScope(string[] cmds)
        {
            if (cmds.Length != 2) {
                Console.WriteLine("Incorrect number of parameters");
                return;
            }

            CBORObject obj = CBORDiagnostics.Parse(cmds[1]);
            if (obj == null) {
                Console.WriteLine("Not a legal CBOR Diagnostic value");
                return;
            }

            if (obj.Type == CBORType.ByteString) {
                UseScopeValue = obj;
            }
            else if (obj.Type == CBORType.TextString) {
                UseScopeValue = obj;
            }
            else if (obj.Type == CBORType.SimpleValue && obj.IsNull) {
                UseScopeValue = null;
            }
            else {
                Console.WriteLine("CBOR type parsed to something  not useful");
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

        private static string UseAudience;

        public static void SetAudience(string[] cmds)
        {
            if (cmds.Length != 2) {
                Console.WriteLine("Incorrect number of args");
            }
            else {
                UseAudience = cmds[1];
            }
        }

        public static void UseJSON(string[] cmds)
        {
            if (cmds.Length != 3) {
                Console.WriteLine("Incorrect number of args");
            }
            else {
                if (authServers.ContainsKey(cmds[1])) {
                    authServers[cmds[1]].UseJSON = (cmds[2].ToLower() == "yes");
                }
                else {
                    Console.WriteLine($"{cmds[1]} is not a registered AS server");
                }
            }
        }

        private static OneKey ClientKey;
        private static int ClientKeyType = 2;

        private static void SetUserKey(string[] cmds)
        {
            if (cmds.Length < 2 || 3 < cmds.Length) {
                Console.WriteLine("Incorrect number of args");
            }
            else {
                if (Program._TlsKeys.ContainsKey(cmds[1])) {
                    ClientKey = Program._TlsKeys[cmds[1]].RawPublicKey;
                }
                else {
                    Console.WriteLine("Can't find TLS key {0}", cmds[1]);
                }

                if (cmds.Length == 3) {
                    switch (cmds[2].ToLower()) {
                    case "kid":
                        ClientKeyType = 1;
                        break;

                    case "key":
                        ClientKeyType = 2;
                        break;

                    default:
                        Console.WriteLine("Unrecognized cnf key type");
                        break;
                    }
                }
            }
        }

        private static OneKey LastKeyFound;
        private static void SaveLastKey(string[] cmds)
        {
            if (cmds.Length != 2) {
                Console.WriteLine("Incorrect number of args");
            }
            else {
                if (LastKeyFound != null) {
                    Program._TlsKeys[cmds[1]] = new Program.OneTlsKey(LastKeyFound);
                }
                else {
                    Console.WriteLine("No last key found to be saved");
                }
            }
        }
    }

}
