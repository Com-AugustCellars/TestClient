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
        
        public static void RunTest(int test)
        {
            if (_oscoap_context == null) {
                _oscoap_context = SecurityContext.DeriveContext(
                    new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23},
                    Encoding.UTF8.GetBytes("client"), Encoding.UTF8.GetBytes("server"), null, AlgorithmValues.AES_CCM_16_64_128);
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
            }
        }

        static void RunTest0()
        {
            CoapClient request = new CoapClient(Program.Host + "/hello/coap") {
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

            if (!response.PayloadString.Equals("Hello World!")) {
                Console.WriteLine("Content value is wrong");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        static void RunTest1()
        {
            CoapClient request = new CoapClient(Program.Host + "/hello/1")
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

        static void RunTest2()
        {
            CoapClient request = new CoapClient(Program.Host + "/hello/2?first=1")
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

        static void RunTest3()
        {
            CoapClient request = new CoapClient(Program.Host + "/hello/3")
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

        static void RunTest4()
        {
            CoapClient request = new CoapClient(Program.Host + "/hello/1")
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

        static void RunTest5()
        {
            CoapClient request = new CoapClient(Program.Host + "/observe")
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

                if (response.HasOption(OptionType.Observe)) {
                    Console.WriteLine("Should not have an observe in the response");
                }

                Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

                count += 1;
                if (count >= 3) {
                    request.Observe().ProactiveCancel();
                }
            });

        }

        static void RunTest6()
        {
            CoapClient request = new CoapClient(Program.Host + "/hello/6")
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

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        static void RunTest7()
        {
            CoapClient request = new CoapClient(Program.Host + "/hello/7")
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

        static void RunTest8()
        {
            CoapClient request = new CoapClient(Program.Host + "/hello/7")
            {
                Timeout = 2000,
                OscoapContext = _oscoap_context
            };

            Response response = request.PutIfNoneMatch(new byte[] { 0x7a }, MediaType.TextPlain);


            if (response == null) {
                Console.WriteLine("Failed to receive response");
                return;
            }

            if (response.StatusCode != StatusCode.PreconditionFailed) {
                Console.WriteLine($"Content type should be 2.12 not {response.StatusCode}");
            }

            Console.WriteLine($"Response Message:\n{Utils.ToString(response)}");

        }

        static void RunTest9()
        {
            CoapClient request = new CoapClient(Program.Host + "/test")
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

    }
}
