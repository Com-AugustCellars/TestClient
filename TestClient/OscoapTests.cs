using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.CoAP.Util;
using Com.AugustCellars.COSE;

namespace TestClient
{
    public static class OscoapTests
    {
        private static SecurityContext _oscoap_context = null;
        private static SecurityContext _oscoap_group_context = null;
        
        public static void RunTest(int test)
        {
            if (_oscoap_context == null) {
                _oscoap_context = SecurityContext.DeriveContext(
                    new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, null,
                    new byte[0], new byte[] {1},
                    new byte[] { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 });
            }

            if (_oscoap_group_context == null) {
                _oscoap_group_context = SecurityContext.DeriveGroupContext(
                    new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
                    new byte[] {0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3}, new byte[0], null, null,
                    new byte[][] {new byte[] {0x1}}, null,
                    new byte[] { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 });

            }

            switch (test) {
                case 0:
                    RunTest0();
                    break;

                case 1:
                    RunTest1();
                    break;

                case 2:
                    RunTest2();
                    break;

                case 3:
                    RunTest3();
                    break;

                case 4:
                    RunTest4();
                    break;

                case 5:
                    RunTest5();
                    break;

                case 6:
                    RunTest6();
                    break;

                case 7:
                    RunTest7();
                    break;

                case 8:
                    RunTest8();
                    break;

                case 9:
                    RunTest9();
                    break;
            case 10:
                RunTest10();
                break;
            case 11:
                RunTest11();
                break;
            case 12:
                RunTest51();
                break;
            case 13:
                RunTest52();
                break;
            case 14:
                RunTest53();
                break;

                case 15:
                    RunTest5_2_2();
                    break;

                case 16:
                    RunTest5_3_1();
                    break;

                case 17:
                    RunTest5_4_1();
                    break;
            }
        }

        static void RunTest0()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/coap") {
                Timeout = 2000
            };

            Response response = request.Get();

            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Content) {
                Console.WriteLine($"Content type should be 2.05 not {response.StatusCode}");
            }

            if (response.HasOption(OptionType.ContentType)) {
                if (response.ContentType != MediaType.TextPlain) {
                    Console.WriteLine($"Content type is set to {response.ContentType} and not 0");
                }
            }
            else {
                Console.WriteLine("Content Type is missing");
            }

            if (response.Payload == null || !response.PayloadString.Equals("Hello World!")) {
                Console.WriteLine("Content value is wrong");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        // Use Context A
        static void RunTest1()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/1")
            {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            Response response = request.Get();

            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Content) {
                Console.WriteLine($"Content type should be 2.05 not {response.StatusCode}");
            }

            if (response.HasOption(OptionType.ContentType)) {
                if (response.ContentType != MediaType.TextPlain) {
                    Console.WriteLine($"Content type is set to {response.ContentType} and not 0");
                }
            }
            else {
                Console.WriteLine("Content Type is missing");
            }

            if (!response.PayloadString.Equals("Hello World!")) {
                Console.WriteLine("Content value is wrong");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        //  Use Security Context C
        static void RunTest2()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/1") {
                Timeout = 2000,
                OscoapContext = _oscoap_group_context
            };

            Response response = request.Get();

            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Content) {
                Console.WriteLine($"Content type should be 2.05 not {response.StatusCode}");
            }

            if (response.HasOption(OptionType.ContentType)) {
                if (response.ContentType != MediaType.TextPlain) {
                    Console.WriteLine($"Content type is set to {response.ContentType} and not 0");
                }
            }
            else {
                Console.WriteLine("Content Type is missing");
            }

            if (!response.PayloadString.Equals("Hello World!")) {
                Console.WriteLine("Content value is wrong");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        //  Use Security Context A
        static void RunTest3()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/2?first=1")
            {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            Response response = request.Get();

            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Content) {
                Console.WriteLine("Content type should be 2.05 not ${response.StatusCode}");
            }

            if (response.HasOption(OptionType.ContentType)) {
                if (response.ContentType != MediaType.TextPlain) {
                    Console.WriteLine($"Content type is set to {response.ContentType} and not 0");
                }
            }
            else {
                Console.WriteLine("Content Type is missing");
            }

            if (response.HasOption(OptionType.ETag)) {
                if (response.ETags.Count() != 1) Console.WriteLine("Number of ETags is incorrect");
                if (!response.ContainsETag(new byte[]{0x2b})) Console.WriteLine("Missing ETag = 0x2b");
            }
            else {
                Console.WriteLine("ETag is missing");
            }

            if (!response.PayloadString.Equals("Hello World!")) {
                Console.WriteLine("Content value is wrong");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        static void RunTest4()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/3")
            {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            Response response = request.Get(MediaType.TextPlain);

            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Content) {
                Console.WriteLine($"Content type should be 2.05 not {response.StatusCode}");
            }

            if (response.HasOption(OptionType.ContentType)) {
                if (response.ContentType != MediaType.TextPlain) {
                    Console.WriteLine($"Content type is set to {response.ContentType} and not 0");
                }
            }
            else {
                Console.WriteLine("Content Type is missing");
            }

            if (response.HasOption(OptionType.MaxAge)) {
                if (response.MaxAge != 5) Console.WriteLine($"Max age is {response.MaxAge} not 5");
            }
            else {
                Console.WriteLine("MaxAge is missing");
            }

            if (!response.PayloadString.Equals("Hello World!")) {
                Console.WriteLine("Content value is wrong");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        static void RunTest5()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/1")
            {
                Timeout = 2000,
                OscoapContext = _oscoap_context
               
            };

            request.Observe(response =>
            {
                if (response == null) {
                    Console.WriteLine("Failed to receive response");
                    return;
                }

                if (response.StatusCode != StatusCode.Content) {
                    Console.WriteLine($"Content type should be 2.05 not {response.StatusCode}");
                }

                if (response.HasOption(OptionType.ContentType)) {
                    if (response.ContentType != MediaType.TextPlain) {
                        Console.WriteLine($"Content type is set to {response.ContentType} and not 0");
                    }
                }
                else {
                    Console.WriteLine("Content Type is missing");
                }

                if (response.HasOption(OptionType.Observe)) {
                    Console.WriteLine("Should not have an observe in the response");
                }

                if (!response.PayloadString.Equals("Hello World!")) {
                    Console.WriteLine("Content value is wrong");
                }

                Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

            });

        }

        static void RunTest6()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/observe1")
            {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            int count = 0;

            request.Observe(response =>
            {
                if (response == null) {
                    Console.WriteLine("Failed to receive response");
                    return;
                }

                if (response.StatusCode != StatusCode.Content) {
                    Console.WriteLine($"Content type should be 2.05 not {response.StatusCode}");
                }

                if (!response.HasOption(OptionType.Observe)) {
                    Console.WriteLine("Should have an observe in the response");
                }

                Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

                count += 1;
                if (count >= 4) {
                    request.Observe().ProactiveCancel();
                }
            });

        }

        static void RunTest7()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/observe2") {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            int count = 0;

            request.Observe(response =>
            {
                if (response == null) {
                    Console.WriteLine("Failed to receive response");
                    return;
                }

                if (response.StatusCode != StatusCode.Content) {
                    Console.WriteLine($"Content type should be 2.05 not {response.StatusCode}");
                }

                if (!response.HasOption(OptionType.Observe)) {
                    Console.WriteLine("Should have an observe in the response");
                }

                Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

                count += 1;
                if (count >= 2) {
                    request.Observe().ProactiveCancel();
                }
            });

        }

        static void RunTest8()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/6")
            {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            Response response = request.Post(new byte[]{0x4a}, MediaType.TextPlain);
            

            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Changed) {
                Console.WriteLine($"Content type should be 2.04 not {response.StatusCode}");
            }

            if (response.PayloadSize != 1 || response.Payload[0] != 0x4a) {
                Console.WriteLine("Payload for the package is wrong - should be 0x4a");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");
        }

        static void RunTest9()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/7")
            {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            Response response = request.PutIfMatch(new byte[] { 0x7a }, MediaType.TextPlain, new byte[][]{new byte[]{0x7b}});


            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Changed) {
                Console.WriteLine($"Content type should be 2.04 not {response.StatusCode}");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        static void RunTest10()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/7")
            {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            Response response = request.PutIfNoneMatch(new byte[] { 0x8a }, MediaType.TextPlain);


            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.PreconditionFailed) {
                Console.WriteLine($"Content type should be 4.12 not {response.StatusCode}");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        static void RunTest11()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/test")
            {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            Response response = request.Delete();


            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Deleted) {
                Console.WriteLine($"Content type should be 2.02 not {response.StatusCode}");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        static void RunTest51()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/1") {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            byte[] saveId = _oscoap_context.Sender.Id;
            _oscoap_context.Sender.Id = new byte[]{25};

            Response response = request.Post(new byte[] { 0x4a }, MediaType.TextPlain);


            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Changed) {
                Console.WriteLine($"Content type should be 2.04 not {response.StatusCode}");
            }

            if (response.PayloadSize != 1 || response.Payload[0] != 0x4a) {
                Console.WriteLine("Payload for the package is wrong - should be 0x4a");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

            _oscoap_context.Sender.Id = saveId;
        }

        static void RunTest52()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/1") {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            byte[] saveKey = _oscoap_context.Sender.Key;
            byte[] newKey = (byte[])saveKey.Clone();
            _oscoap_context.Sender.Key = newKey;
            newKey[0] += 1;

            Response response = request.Post(new byte[] { 0x4a }, MediaType.TextPlain);


            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Changed) {
                Console.WriteLine($"Content type should be 2.04 not {response.StatusCode}");
            }

            if (response.PayloadSize != 1 || response.Payload[0] != 0x4a) {
                Console.WriteLine("Payload for the package is wrong - should be 0x4a");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

            _oscoap_context.Sender.Key = saveKey;
        }

        static void RunTest5_2_2()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/1") {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            _oscoap_context.Sender.BaseIV[_oscoap_context.Sender.BaseIV.Length-1] -= 1;

            Response response = request.Get();


            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Changed) {
                Console.WriteLine($"Content type should be 2.04 not {response.StatusCode}");
            }

            if (response.PayloadSize != 1 || response.Payload[0] != 0x4a) {
                Console.WriteLine("Payload for the package is wrong - should be 0x4a");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

            request = new CoapClient(Program.Host + "/oscore/hello/1") {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            response = request.Get();
        }

        static void RunTest53()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/1") {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            byte[] saveKey = _oscoap_context.Recipient.Key;
            byte[] newKey = (byte[])saveKey.Clone();
            _oscoap_context.Sender.Key = newKey;
            newKey[0] += 1;

            Response response = request.Post(new byte[] { 0x4a }, MediaType.TextPlain);


            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Changed) {
                Console.WriteLine($"Content type should be 2.04 not {response.StatusCode}");
            }

            if (response.PayloadSize != 1 || response.Payload[0] != 0x4a) {
                Console.WriteLine("Payload for the package is wrong - should be 0x4a");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

            _oscoap_context.Recipient.Key = saveKey;
        }

        static void RunTest5_3_1()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/coap") {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };


            Response response = request.Post(new byte[] { 0x4a }, MediaType.TextPlain);


            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Changed) {
                Console.WriteLine($"Content type should be 2.04 not {response.StatusCode}");
            }

            if (response.PayloadSize != 1 || response.Payload[0] != 0x4a) {
                Console.WriteLine("Payload for the package is wrong - should be 0x4a");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        static void RunTest5_4_1()
        {
            CoapClient request = new CoapClient(Program.Host + "/oscore/hello/1") {
                Timeout = 2000
            };

            Response response = request.Post(new byte[] { 0x4a }, MediaType.TextPlain);

            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.Changed) {
                Console.WriteLine($"Content type should be 2.04 not {response.StatusCode}");
            }

            if (response.PayloadSize != 1 || response.Payload[0] != 0x4a) {
                Console.WriteLine("Payload for the package is wrong - should be 0x4a");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");
        }
    }
}
