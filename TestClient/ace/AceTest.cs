using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Util;
using PeterO.Cbor;

namespace TestClient
{
    class AceTest
    {
        public static void Test(string[] cmds)
        {
            if (cmds.Length == 2) {
                switch (cmds[1]) {
                    case "1.1":
                        Test_1_1();
                        break;

                    case "2.2":
                        Test_2_2();
                        break;
                }
            }
        }


        private static void Test_1_1()
        {
            // Test 1.1 - TLS to AS,  Send request
            // [Client1, AS]
            // 
            Request request = Program.NewRequest("GET", new Uri(Program.Host, "/ace/helloWorld"));
            Program.AddEndPoint(request);
            request.PayloadString = "Hi Mom";
            request.ContentFormat = MediaType.ApplicationCbor;
            try {
                request.Send();
                Response response = request.WaitForResponse(1000 * 5);
                if (response == null) {
                    Console.WriteLine("FAIL:  No response ");
                    return;
                }

                if (response.StatusCode != StatusCode.Unauthorized) {
                    Console.WriteLine("FAIL:  Wrong status code {0}", response.StatusCode);
                    return;
                }

                if (response.ContentFormat != MediaType.ApplicationCbor) {
                    Console.WriteLine("FAIL: Incorrect content type - returned {0}", response.ContentFormat);
                }

                CBORObject asInfo = CBORObject.DecodeFromBytes(response.Payload);
                Console.WriteLine("Return content: {0}", asInfo);

            }
            catch (Exception e) {
                Console.WriteLine("FAIL: Execution occured {0}", e);
            }
        }

        private static void Test_2_2()
        {
           // Request request = Program.NewRequest("");
        }
    }
}
