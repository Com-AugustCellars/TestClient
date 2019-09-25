using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.CoAP.Util;
using Com.AugustCellars.COSE;
using PeterO.Cbor;

namespace TestClient
{
    public class Oscore
    {

        public static void Register(DispatchTable table)
        {
            //  OSCORE Functions
            table.Add("add-oscore", new Dispatch("Add a OSCORE key to the key set", "add-oscore key-name key-value", AddOscoreKey));
            table.Add("add-group-oscore", new Dispatch("Add a Group OSCORE key to the key set", "add-oscore key-name key-value", AddGroupOscoreKey));
            table.Add("set-oscore", new Dispatch("Select an score key to use", "set-oscore [key-name]", UseOscoreKey));
            table.Add("use-oscore", new Dispatch("Select an score key to use", "use-oscore [key-name]", UseOscoreKey));
            table.Add("run-oscore-test", new Dispatch("Run a specific oscore text", "run-score-test testNumber", RunOscoreText));
            table.Add("set-oscore-piv", new Dispatch("Set the PIV value for the current oscore key", "set-oscore-piv pivNumber", SetOscorePiv));
            table.Add("gen-oscore", new Dispatch("Generate Group OSCORE parameters", "gen-oscore", GenOscore));
        }

        private static void AddOscoreKey(string[] cmds)
        {
            if (cmds.Length != 3) {
                Console.WriteLine("Incorrect number of arguments: " + cmds.Length);
                return;
            }

            CBORObject cbor = CBORDiagnostics.Parse(cmds[2]);
            byte[] salt = null;
            if (cbor.ContainsKey(CBORObject.FromObject(6))) {
                salt = cbor[CBORObject.FromObject(6)].GetByteString();
            }

            byte[] contextId = null;
            if (cbor.ContainsKey(CBORObject.FromObject(7))) {
                contextId = cbor[CBORObject.FromObject(7)].GetByteString();
            }

            SecurityContext ctx = SecurityContext.DeriveContext(
                cbor[CBORObject.FromObject(1)].GetByteString(),
                contextId,
                cbor[CBORObject.FromObject(2)].GetByteString(),
                cbor[CBORObject.FromObject(3)].GetByteString(), salt,
                null /*cbor[CoseKeyKeys.Algorithm]*/);

            Program._OscoreKeys.Add(cmds[1], ctx);
        }

        /// <summary>
        /// What the CBOR structure needs to look like:
        /// 
        /// </summary>
        /// <param name="cmds"></param>
        private static void AddGroupOscoreKey(string[] cmds)
        {
            if (cmds.Length != 3) {
                Console.WriteLine("Incorrect number of arguments: " + cmds.Length);
                return;
            }

            CBORObject cbor = CBORDiagnostics.Parse(cmds[2]);
            byte[] salt = null;
            if (cbor.ContainsKey(CoseKeyKeys.slt)) {
                salt = cbor[CoseKeyKeys.slt].GetByteString();
            }

            SecurityContext ctx = SecurityContext.DeriveGroupContext(cbor[CoseKeyParameterKeys.Octet_k].GetByteString(),
                cbor[CBORObject.FromObject("GroupID")].GetByteString(),
                cbor[CBORObject.FromObject("sender")][CBORObject.FromObject("ID")].GetByteString(),
                cbor["sender"]["sign"][CoseKeyKeys.Algorithm],
                new OneKey(cbor["sender"]["sign"]),
                null, null, salt, cbor[CoseKeyKeys.Algorithm]);
            ctx.CountersignParams = cbor["ParCS"];
            ctx.CountersignKeyParams = cbor["ParCSKey"];

            foreach (CBORObject recipient in cbor[CBORObject.FromObject("recipients")].Values) {
                OneKey signKey = null;
                if (recipient.ContainsKey("sign")) {
                    signKey = new OneKey(recipient["sign"]);
                }

                ctx.AddRecipient(recipient[CBORObject.FromObject("ID")].GetByteString(), signKey);
            }

            ctx.Locate = (context, kid) => {
                Console.WriteLine("Looking for a kid with a value of " + ByteArrayUtils.ToHexString(kid));
                return null;
            };

            Program._OscoreKeys.Add(cmds[1], ctx);
        }

        private static void UseOscoreKey(string[] cmds)
        {
            if (cmds.Length != 2) {
                Console.WriteLine("Incorrect number of arguments: " + cmds.Length);
                return;
            }

            if (cmds[1] == "NONE") {
                Program._CurrentOscore = null;
                return;
            }

            if (!Program._OscoreKeys.ContainsKey(cmds[1])) {
                Console.WriteLine($"Oscore Key {cmds[1]} is not defined");
                return;
            }

            Program._CurrentOscore = Program._OscoreKeys[cmds[1]];
        }

        private static void RunOscoreText(string[] cmds)
        {

            OscoreTests.RunTest(Int32.Parse(cmds[1]));
        }

        private static void SetOscorePiv(string[] cmds)
        {
            Program._CurrentOscore.Sender.SequenceNumber = Int32.Parse(cmds[1]);
        }

        private static void GenOscore(string[] cmds)
        {
            int count = int.Parse(cmds[1]);
            int keyType = int.Parse(cmds[2]);
            string algParams = cmds[3];

            for (int i = 0; i < count; i++) {
                OneKey key = OneKey.GenerateKey(null, CBORObject.FromObject(keyType), algParams);
                Console.WriteLine("*** " + key.EncodeToCBORObject().ToString());
            }
        }
    }
}
