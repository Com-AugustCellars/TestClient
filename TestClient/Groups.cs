using System;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.CoAP.OAuth;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.COSE;
using Com.AugustCellars.WebToken;
using Org.BouncyCastle.Security;
using PeterO.Cbor;
using Request = Com.AugustCellars.CoAP.Request;
using Oauth = Com.AugustCellars.CoAP.OAuth;
using Response = Com.AugustCellars.CoAP.Response;

namespace TestClient
{
    class Groups
    {
        class GroupData
        {
            public byte[] ServerNonce;
            public byte[] SignNonce;
            public CBORObject SignInfo;
            public byte[] PubKeyEnc;
        }

        public static void FillDispatchTable(DispatchTable table)
        {
            table.Add("KdcToken", new Dispatch("KdcToken <AS> <Audience> <Scope> <OscoreKeys> <Kdc> <store>", "Ask an AS for a KDC token", KdcToken));
            table.Add("kdc-join", new Dispatch("kdc-join", "Try to join ", KdcJoin));
        }

        public static void KdcToken(string[] cmds)
        {
            if (cmds.Length != 7) {
                Console.WriteLine("Incorrect argument Count: KdcToken <AS> <Audience> <Scope> <OscoreKeys> <Kdc> <Store>");
                return;
            }

            Request request = new Request(Method.POST) {
                URI = new Uri(cmds[1])
            };

            Oauth.Request oRequest = new Oauth.Request(Oauth.Request.GrantType_ClientToken) {
                Audience = cmds[2],
                Scope = CBORObject.FromObject(cmds[3])
            };

            request.Payload = oRequest.EncodeToBytes();
            request.ContentType = MediaType.ApplicationAceCbor;
            request.OscoreContext = Program._OscoreKeys[cmds[4]];

            request.Send();
            Response response = request.WaitForResponse();
            if (response.StatusCode != StatusCode.Created) {
                Console.WriteLine($"Error with response from the AS - Code is {response.StatusCode}");
                return;
            }

            Oauth.Response oResponse = Oauth.Response.FromCBOR(response.Payload);

            Confirmation cnf = oResponse.Confirmation;
            byte[][] oscoreSalts = new byte[2][];

            request = new Request(Method.POST)
            {
                URI = new Uri(cmds[5])
            };

            CBORObject kdcRequest = CBORObject.NewMap();
            kdcRequest.Add(Oauth_Parameter.Access_Token.Key, oResponse.Token);
            if (cnf.AsCBOR.ContainsKey(CBORObject.FromObject(Confirmation.ConfirmationIds.COSE_OSCORE))) {
                oscoreSalts[0] = SecureRandom.GetNextBytes(new SecureRandom(), 8);
                kdcRequest.Add(Oauth_Parameter.CNonce.Key, CBORObject.FromObject(oscoreSalts[0]));
                request.ContentFormat = MediaType.ApplicationAceCbor;
            }

            request.Payload = kdcRequest.EncodeToBytes();


            request.Send();
            response = request.WaitForResponse();

            if (response.StatusCode != StatusCode.Created) {
                Console.WriteLine("Failure");
                return;
            }

            Console.WriteLine("Successfully posted to KDC");
            CBORObject cborResponse = CBORObject.DecodeFromBytes(response.Payload);

            GroupData groupData = new GroupData();
            if (cborResponse.ContainsKey(Oauth_Parameter.CNonce.Key)) {
                groupData.ServerNonce = cborResponse[Oauth_Parameter.CNonce.Key].GetByteString();
            }

            if (cborResponse.ContainsKey("sign_info")) {
                groupData.SignInfo = CBORObject.DecodeFromBytes(cborResponse["sign_info"].GetByteString());
            }
            else {
                groupData.SignInfo = CBORObject.DecodeFromBytes(new byte[] {0x83, 0x27, 0x06, 0x82, 0x01, 0x06});
            }

            if (cborResponse.ContainsKey("pub_key_enc")) {
                groupData.PubKeyEnc = cborResponse["pub_key_enc"].GetByteString();
            }

            groupData.SignNonce = cborResponse["SignNonce"].GetByteString();

            if (cnf.AsCBOR.ContainsKey(CBORObject.FromObject(Confirmation.ConfirmationIds.COSE_OSCORE))) {
                CBORObject oscoreContext = cnf.AsCBOR[CBORObject.FromObject(Confirmation.ConfirmationIds.COSE_OSCORE)];

                byte[] salt = new byte[0];
                if (oscoreContext.ContainsKey(CBORObject.FromObject(6))) salt = oscoreContext[CBORObject.FromObject(CBORObject.FromObject(6))].GetByteString();
                CBORObject alg = null;
                if (oscoreContext.ContainsKey(CBORObject.FromObject(5))) alg = oscoreContext[CBORObject.FromObject(5)];
                CBORObject kdf = null;
                if (oscoreContext.ContainsKey(CBORObject.FromObject(4))) kdf = oscoreContext[CBORObject.FromObject(4)];
                byte[] keyContext = null;
                if (oscoreContext.ContainsKey(CBORObject.FromObject(7))) {
                    keyContext = oscoreContext[CBORObject.FromObject(7)].GetByteString();
                }

                oscoreSalts[1] = cborResponse[Oauth_Parameter.CNonce.Key].GetByteString();

                byte[] newSalt = new byte[salt.Length + oscoreSalts[0].Length + oscoreSalts[1].Length];
                Array.Copy(salt, newSalt, salt.Length);
                Array.Copy(oscoreSalts[0], 0, newSalt, salt.Length, oscoreSalts[0].Length);
                Array.Copy(oscoreSalts[1], 0, newSalt, salt.Length + oscoreSalts[0].Length, oscoreSalts[1].Length);

                SecurityContext oscoapContext = SecurityContext.DeriveContext(
                    oscoreContext[CBORObject.FromObject(1)].GetByteString(), keyContext,
                    oscoreContext[CBORObject.FromObject(2)].GetByteString(),
                    oscoreContext[CBORObject.FromObject(3)].GetByteString(),
                    newSalt, alg, kdf);
                oscoapContext.UserData = groupData;

                Program._OscoreKeys.Add(cmds[6], oscoapContext);
            }
            else if (cnf.AsCBOR.ContainsKey(CBORObject.FromObject(Confirmation.ConfirmationIds.COSE_Key))) {
                TlsKeyPair tlsKey = new TlsKeyPair(cnf.Key);
                tlsKey.PrivateKey.UserData = groupData;

                Program._TlsKeys.Add(cmds[5], new TlsKeyPair(cnf.Key));
            }
            else {
                Console.WriteLine("Don't know how to get the key");
            }
        }

        private static void KdcJoin(string[] cmds)
        {
            if (cmds.Length != 3) {
                Console.WriteLine("Incorrect number of parameters");
                return;
            }

            if ((Program._CurrentOscore == null) || (Program._CurrentOscore.UserData == null) ||
                !(Program._CurrentOscore.UserData is GroupData)) {
                Console.WriteLine("Can't use the current OSCORE context");
                return;
            }

            GroupData groupData = (GroupData) Program._CurrentOscore.UserData;

            OneKey signKey = OneKey.GenerateKey(null, GeneralValues.KeyType_OKP, "Ed25519");

            byte[] signature = Signer.Sign(groupData.SignNonce, groupData.SignInfo[0], signKey);

            CBORObject join = CBORObject.NewMap();
            CBORObject j2 = CBORObject.NewMap();
            j2.Add(Confirmation.ConfirmationIds.COSE_Key, signKey.AsCBOR());

            join.Add("type", 1);
            join.Add("client_cred", j2);
            join.Add("client_cred_verify", signature);

            Request request = new Request(Method.POST) {
                URI = new Uri(cmds[1]),
                Payload = @join.EncodeToBytes(),
                ContentType = MediaType.ApplicationCbor,
                OscoreContext = Program._CurrentOscore
            };


            request.Send();
            Response response = request.WaitForResponse();

            if (response == null || response.StatusCode != StatusCode.Changed) {
                Console.WriteLine("Error in the response");
                return;
            }

            CBORObject respBody = CBORObject.DecodeFromBytes(response.Payload);


        }
    }
}
