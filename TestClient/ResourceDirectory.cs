using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.EndPoint.Resources;
using Com.AugustCellars.CoAP.Server;
using Com.AugustCellars.CoAP.Server.Resources;
using Com.AugustCellars.CoAP.Util;

namespace TestClient
{
    class ResourceDirectory
    {
        private static string Test3Location;
        private static string Test4Location;
        private static string Test5Location;
        private static string Test6Location;

        private static string ResourceRegister = "/rd";
        private static string ResourceLookup = "/rd-lookup/res";
        private static string EndpointLookup = "/rd-lookup/ep";
        private static string GroupLookup = "/rd-lookup/gp";
        private static string GroupRegister = "/rd-group";

        public static void AddCommands(DispatchTable table)
        {
            table.Add("rd_test", new Dispatch("Run my internal Resource Directory Tests", "rd_test <test number>", RunTest));
            table.Add("rd_clean", new Dispatch("delete all resources", "rd_clean", CleanAll));
        }

        public static void RunTest(string[] cmds)
        {
            int testNumber = int.Parse(cmds[1]);

            switch (testNumber) {
            default:
                Console.WriteLine("Unrecognized test number");
                break;

            case 1:
                RunTest1(cmds);
                break;

            case 2:
                RunTest2(cmds);
                break;

            case 3:
                RunTest3(cmds);
                break;

            case 4:
                RunTest4(cmds);
                break;

            case 5:
                RunTest5(cmds);
                break;

            case 6:
                RunTest6(cmds);
                break;

            case 7:
                RunTest7(cmds);
                break;

            case 8:
                RunTest8(cmds);
                break;

            case 9:
                RunTest9(cmds);
                break;

            case 10:
                RunTest10(cmds);
                break;

            case 11:
                RunTest11(cmds);
                break;

            case 12:
                RunTest12(cmds);
                break;

            case 13:
                RunTest13(cmds);
                break;

            case 14:
                RunTest14(cmds);
                break;

            case 15:
                RunTest15(cmds);
                break;
            }
        }

        private static void RunTest1(string[] cmds)
        {
            //  Multicast Request
            //  NON GET /.well-known/core?rt=core.rd
            // Accept=40 
            Console.WriteLine("We don't do multicast for clients or servers at this time");

            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = "/.well-known/core",
                UriQuery = "rt=core.rd",
                Timeout = 20 * 1000
            };
            cl.UseNONs();

            Response r1 = cl.Get(MediaType.ApplicationLinkFormat);
            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            if (r1.StatusCode != StatusCode.Content) {
                Console.WriteLine("Incorrect return code");
            }

            if (r1.StatusCode < StatusCode.BadRequest) {
                if (r1.ContentFormat != MediaType.ApplicationLinkFormat) {
                    Console.WriteLine("Incorrect Media Type");
                }
            }

            Console.WriteLine(Utils.ToString(r1));
        }

        private static void RunTest2(string[] cmds)
        {
            //  Multicast Request
            //  Multicast Request
            //  NON GET /.well-known/core?rt=core.rd*
            // Accept=40 

            Console.WriteLine("We don't do multicast for clients or servers at this time");

            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = "/.well-known/core",
                UriQuery = "rt=core.rd*",
                Timeout = 20 * 1000
            };
            cl.UseNONs();

            IEnumerable<WebLink> d = cl.Discover("rt=core.r*", MediaType.ApplicationLinkFormat);

            foreach (WebLink w in d) {
                foreach (string s in w.Attributes.GetResourceTypes()) {
                    switch (s) {
                    case "core.rd":
                        ResourceRegister = w.Uri;
                        break;

                    case "core.rd-lookup-res":
                        ResourceLookup = w.Uri;
                        break;

                    case "core.rd-group":
                        GroupRegister = w.Uri;
                        break;

                    case "core.rd-lookup-gp":
                        GroupLookup = w.Uri;
                        break;

                    case "core.rd-lookup-ep":
                        EndpointLookup = w.Uri;
                        break;
                    }
                }
            }
        }


        private static void RunTest3(string[] cmds)
        {
            //  Simple registration - 

            RdServer server = new RdServer();
            server.Start();
            server.PostTo();

            Thread.Sleep(20 * 1000);

            server.Stop();

            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = EndpointLookup,
                UriQuery = "ep=node1",
                Timeout = 20*1000
            };

            Response r1 = cl.Get(MediaType.ApplicationLinkFormat);
            if (r1 != null && r1.StatusCode == StatusCode.Content) {
                string ss = r1.PayloadString.Substring(1);
                int i = ss.IndexOf('>');
                Test3Location = ss.Substring(0, i);
            }

            Console.WriteLine("Test 3 done");

#if false
            if (cmds.Length == 2) {
                //  Do it as a third party.
                CoapClient cl = new CoapClient(Program.Host) {
                    UriPath = "/rd",
                    Timeout = 20 * 1000,
                    UriQuery = "lt=6000&ep=node1"
                };
                Response r1 = cl.Post(
                    "</sensors/temp>;ct=41;rt=\"temperature-c\";if=sensor;anchor=\"coap://spurious.example.com:5683\"," +
                    "</sensors/light>;ct=41;rt=\"light-lux\";if=sensor",
                    MediaType.ApplicationLinkFormat);
                if (r1 == null) {
                    Console.WriteLine("No response message retrieved");
                    return;
                }

                Test3Location = r1.LocationPath;
                return;


            }

            if (cmds.Length != 4) {
                Console.WriteLine("Should be 'rd_test 1 <server to do Simple Registration> <endpoint name>'");
                return;
            }

            CoapClient client = new CoapClient(cmds[2]) {
                UriPath = "/rd/post2",
                Timeout = 20 * 1000
            };

            Response r = client.Post(Program.Host.ToString() + " " + cmds[3]);
            if (r == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }
            else if (r.Code != (int) StatusCode.Changed) {
                Console.WriteLine("Unexpected status code {0}.{1} returned", r.Code / 32, r.Code % 32);
                return;
            }
#endif
        }

        static void RunTest4(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = ResourceRegister,
                UriQuery = "ep=node2",
                Timeout = 20 * 1000
            };
            Response r1 = cl.Post(
                "</temp>;rt=\"temperature\";ct=0," +
                "</light>;rt=\"light-lux\";ct=0," +
                "</t>;anchor=\"sensors/temp\";rel=\"alternate\"," +
                "<http://www.example.com/sensors/t123>;anchor=\"sensors/temp\";rel=\"describedby\"",
                MediaType.ApplicationLinkFormat);
            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            Test4Location = r1.LocationPath;
            return;
        }

        static void RunTest5(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = ResourceRegister,
                UriQuery = "ep=node3",
                Timeout = 20 * 1000
            };
            Response r1 = cl.Post(
                "</light/left>;rt=\"light\";ct=0," +
                "</light/middle>;rt=\"light\";ct=0," +
                "</light/right>;rt=\"light\";ct=0",
                MediaType.ApplicationLinkFormat);
            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            Test5Location = r1.LocationPath;
        }

        static void RunTest6(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = GroupRegister,
                UriQuery = "gp=lights&base=coap://[ff35:30:2001:db8::1]/",
                Timeout = 20 * 1000
            };
            Response r1 = cl.Post(
                $"<{Test3Location}>,<{Test4Location}>",
                MediaType.ApplicationLinkFormat);
            
            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            Test6Location = r1.LocationPath;
        }

        static void RunTest7(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = GroupLookup,
                Timeout = 20 * 1000
            };
            Response r1 = cl.Get(MediaType.ApplicationLinkFormat);

            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            if (r1.StatusCode != StatusCode.Content) {
                Console.WriteLine("Incorrect return code");
            }

            if (r1.StatusCode < StatusCode.BadRequest) {
                if (r1.ContentFormat != MediaType.ApplicationLinkFormat) {
                    Console.WriteLine("Incorrect Media Type");
                }
            }

            Console.WriteLine(Utils.ToString(r1));
        }

        static void RunTest8(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = ResourceLookup,
                UriQuery = "rt=temperature",
                Timeout = 20 * 1000
            };
            Response r1 = cl.Get(MediaType.ApplicationLinkFormat);

            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            if (r1.StatusCode != StatusCode.Content) {
                Console.WriteLine("Incorrect return code");
            }

            if (r1.StatusCode < StatusCode.BadRequest) {
                if (r1.ContentFormat != MediaType.ApplicationLinkFormat) {
                    Console.WriteLine("Incorrect Media Type");
                }
            }

            Console.WriteLine(Utils.ToString(r1));
        }

        static void RunTest9(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = Test6Location,
                Timeout = 20 * 1000
            };
            Response r1 = cl.Delete();

            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            if (r1.StatusCode != StatusCode.Deleted) {
                Console.WriteLine("Incorrect return code");
            }

            Console.WriteLine(Utils.ToString(r1));
        }

        static void RunTest10(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = EndpointLookup,
                UriQuery = "rt=temperature",
                Timeout = 20 * 1000
            };
            Response r1 = cl.Get(MediaType.ApplicationLinkFormat);

            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            if (r1.StatusCode != StatusCode.Content) {
                Console.WriteLine("Incorrect return code");
            }

            if (r1.StatusCode < StatusCode.BadRequest) {
                if (r1.ContentFormat != MediaType.ApplicationLinkFormat) {
                    Console.WriteLine("Incorrect Media Type");
                }
            }

            Console.WriteLine(Utils.ToString(r1));
        }

        static void RunTest11(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = Test3Location,
                Timeout = 20 * 1000
            };
            Response r1 = cl.Get(MediaType.ApplicationLinkFormat);

            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            if (r1.StatusCode != StatusCode.Content) {
                Console.WriteLine("Incorrect return code");
            }

            if (r1.StatusCode < StatusCode.BadRequest) {
                if (r1.ContentFormat != MediaType.ApplicationLinkFormat) {
                    Console.WriteLine("Incorrect Media Type");
                }
            }

            Console.WriteLine(Utils.ToString(r1));
        }

        static void RunTest12(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = Test3Location,
                Timeout = 20 * 1000
            };
            Response r1 = cl.Delete();

            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            if (r1.StatusCode != StatusCode.Deleted) {
                Console.WriteLine("Incorrect return code");
            }

            Console.WriteLine(Utils.ToString(r1));
        }

        static void RunTest13(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = Test4Location,
                UriQuery = "base=coaps://new.example.com:5684",
                Timeout = 20 * 1000
            };
            Response r1 = cl.Post((byte[]) null, MediaType.Undefined);

            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            if (r1.StatusCode != StatusCode.Changed) {
                Console.WriteLine("Incorrect return code");
            }

            Console.WriteLine(Utils.ToString(r1));
        }

        static void RunTest14(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = GroupLookup,
                Timeout = 20 * 1000
            };
            Response r1 = cl.Get(MediaType.ApplicationLinkFormat);

            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            if (r1.StatusCode != StatusCode.Content) {
                Console.WriteLine("Incorrect return code");
            }

            if (r1.StatusCode < StatusCode.BadRequest) {
                if (r1.ContentFormat != MediaType.ApplicationLinkFormat) {
                    Console.WriteLine("Incorrect Media Type");
                }
            }

            Console.WriteLine(Utils.ToString(r1));
        }

        static void RunTest15(string[] cmds)
        {
            //  Do it as a third party.
            CoapClient cl = new CoapClient(Program.Host) {
                UriPath = ResourceLookup,
                Timeout = 20 * 1000
            };
            Response r1 = cl.Get(MediaType.ApplicationLinkFormat);

            if (r1 == null) {
                Console.WriteLine("No response message retrieved");
                return;
            }

            if (r1.StatusCode != StatusCode.Content) {
                Console.WriteLine("Incorrect return code");
            }

            if (r1.StatusCode < StatusCode.BadRequest) {
                if (r1.ContentFormat != MediaType.ApplicationLinkFormat) {
                    Console.WriteLine("Incorrect Media Type");
                }
            }

            Console.WriteLine(Utils.ToString(r1));
        }

        static void RunTest2X(string[] cmds)
        {
            int useContentFormat = MediaType.ApplicationLinkFormat;

            if (cmds.Length > 2) {
                switch (cmds[2].ToLower()) {
                    case "cbor":
                        useContentFormat = MediaType.ApplicationLinkFormatCbor;
                        break;

                    case "json":
                        useContentFormat = MediaType.ApplicationLinkFormatJson;
                        break;

                    default:
                        Console.WriteLine("Unrecognized content type");
                        return;
                }
            }
            CoapClient c = new CoapClient(Program.Host);
            IEnumerable<WebLink> d = c.Discover("rt=core.r*", MediaType.ApplicationLinkFormat);

            string endpointRegister = null;
            string endpointLookup = null;
            string groupRegister = null;
            string groupLookup = null;
            string resourceLookup = null;

            foreach (WebLink w in d) {
                foreach (string s in w.Attributes.GetResourceTypes()) {
                    switch (s) {
                        case "core.rd":
                            endpointRegister = w.Uri;
                            break;

                        case "core.rd-lookup-res":
                            resourceLookup = w.Uri;
                            break;

                        case "core.rd-group":
                            groupRegister = w.Uri;
                            break;

                        case "core.rd-lookup-gp":
                            groupLookup = w.Uri;
                            break;

                        case "core.rd-lookup-ep":
                            endpointLookup = w.Uri;
                            break;
                    }
                }
            }

            if (endpointRegister == null) {
                Console.WriteLine("No endpoint registration resource found");
                return;
            }

            //  Register three endpoints and get their locations

            Uri uri1 = new Uri(Program.Host, endpointRegister);
            c = new CoapClient(uri1);
            c.UriQuery = "ep=endpoint1&con=coap://sensor1&lt=240";

            Response r =
                c.Post(EncodeResources(
                    "</sensors/temp>;ct=41;rt=\"temperature-c\";if=sensor,</sensors/light>;ct=41;rt=\"light-lux\";if=sensor;obs", 
                           useContentFormat),
                    useContentFormat);
            string endpoint1Location = r.Location;

            c.UriQuery = "ep=endpoint2&d=floor3&con=coap://sensor2&lt=120";
            r = c.Post(EncodeResources(
                           "</sensors/temp>;ct=41;rt=\"temperature-c\";if=sensor,</sensors/light>;ct=41;rt=\"light-lux\";if=sensor",
                           useContentFormat), useContentFormat);
            string endpoint2Location = r.Location;

            c.UriQuery = "ep=endpoint3&con=coaps://door1&even=yes&lt=120";
            r = c.Post(EncodeResources(
                           "</door/state>;ct=41;rt=doorx;if=senseor,</door/lock>,</door/desc>;ct=0;anchor=\"https://doorcomany/locks?locktype=1\";rt=description",
                           useContentFormat), useContentFormat);
            string endpoint3Location = r.Location;

            //  do end point queries
            if (endpointLookup == null) {
                Console.WriteLine("No endpoint lookup resource found");
            }
            else {
                uri1 = new Uri(Program.Host, endpointLookup);
                c = new CoapClient(uri1);
                d = c.Discover(endpointLookup, null, useContentFormat);
                Console.WriteLine("Query Endpoint all - expect 3");
                foreach (WebLink w in d) {
                    Console.WriteLine("  " + w.ToString());
                }

                d = c.Discover(endpointLookup, "if=sensor", useContentFormat);
                Console.WriteLine("Query for if=sensor");
                foreach (WebLink w in d) {
                    Console.WriteLine("  " + w.ToString());
                }

                d = c.Discover(endpointLookup, "even=yes", useContentFormat);
                Console.WriteLine("Query for even=yes");
                foreach (WebLink w in d) {
                    Console.WriteLine("  " + w.ToString());
                }
            }

            if (resourceLookup == null) {
                Console.WriteLine("No resource lookup resource found");
            }
            else {
                uri1 = new Uri(Program.Host, resourceLookup);
                c = new CoapClient(uri1);

                d = c.Discover(resourceLookup, null, useContentFormat);
                Console.WriteLine("Query resources all");
                foreach (WebLink w in d) {
                    Console.WriteLine("  " + w.ToString());
                }

                d = c.Discover(resourceLookup, "if=sensor", useContentFormat);
                Console.WriteLine("Query resource - if=sensor");
                foreach (WebLink w in d) {
                    Console.WriteLine("  " + w.ToString());
                }

                d = c.Discover(resourceLookup, "ep=endpoint1", useContentFormat);
                Console.WriteLine("Query resource - endpoint1");
                foreach (WebLink w in d) {
                    Console.WriteLine("  " + w.ToString());
                }
            }


            if (groupRegister != null) {
                uri1 = new Uri(Program.Host, groupRegister);
                c = new CoapClient(uri1);
                c.UriQuery = "gp=lights";
                r = c.Post($"<{endpoint1Location}>,<{endpoint2Location}>", MediaType.ApplicationLinkFormat);

                string group1Location = r.Location;

                c.UriQuery = "gp=all&con=coap://[MD1]:8080&odd=no";
                r = c.Post($"<{endpoint1Location}>,<{endpoint2Location}>,<{endpoint3Location}>",
                           MediaType.ApplicationLinkFormat);

                if (groupLookup != null) {
                    uri1 = new Uri(Program.Host, groupLookup);
                    c = new CoapClient(uri1);

                    //  Get all of the groups
                    d = c.Discover(groupLookup, null, useContentFormat);
                    Console.WriteLine("Retrieve all groups - expect 3");
                    foreach (WebLink w in d) {
                        Console.WriteLine("  " + w.ToString());
                    }

                    // Get all groups w/ doors
                    d = c.Discover(groupLookup, "rt=doorx", useContentFormat);
                    Console.WriteLine("Retrieve groups w/ rt=doors - expect 1");
                    foreach (WebLink w in d) {
                        Console.WriteLine("  " + w.ToString());
                    }
                }
            }
        }

        private static  void CleanAll(string[] cmds)
        {
            CoapClient c = new CoapClient(Program.Host);
            IEnumerable<WebLink> d = c.Discover("rt=core.rd*", MediaType.ApplicationLinkFormat);

            string endpointRegister = null;
            string endpointLookup = null;
            string groupRegister = null;
            string groupLookup = null;
            string resourceLookup = null;

            foreach (WebLink w in d) {
                foreach (string s in w.Attributes.GetResourceTypes()) {
                    switch (s) {
                    case "core.rd":
                        endpointRegister = w.Uri;
                        break;

                    case "core.rd-lookup-res":
                        resourceLookup = w.Uri;
                        break;

                    case "core.rd-group":
                        groupRegister = w.Uri;
                        break;

                    case "core.rd-lookup-gp":
                        groupLookup = w.Uri;
                        break;

                    case "core.rd-lookup-ep":
                        endpointLookup = w.Uri;
                        break;
                    }
                }
            }

            if (groupLookup != null) {
                d = c.Discover(groupLookup, null, MediaType.ApplicationLinkFormat);
                foreach (WebLink w in d) {
                    c.UriPath = w.Uri;
                    c.Delete();
                }
            }

            d = c.Discover(endpointLookup, null, MediaType.ApplicationLinkFormat);
            foreach (WebLink w in d) {
                c.UriPath = w.Uri;
                c.Delete();
            }
        }

        private static byte[] EncodeResources(string sourceResouces, int mediaType)
        {
            RemoteResource rr = RemoteResource.NewRoot(sourceResouces, mediaType);

            switch (mediaType) {
            case MediaType.ApplicationLinkFormat:
                string x = LinkFormat.Serialize(rr);
                return Encoding.UTF8.GetBytes(x);

            case MediaType.ApplicationLinkFormatCbor:
                return LinkFormat.SerializeCbor(rr, null);

            case MediaType.ApplicationLinkFormatJson:
                return Encoding.UTF8.GetBytes(LinkFormat.SerializeJson(rr, null));

            default:
                return null;
            }
        }
    }

    class RdServer : CoapServer
    {
        public RdServer() : base(null, 5691)
        {
            IResource r = new NopResource("sensors");
            Add(r);
            
            r.Add(new NopResource("temp"));
            r.Add(new NopResource("light"));

            // 
            //    </ sensors / temp >; ct = 41; rt = "temperature-c"; if= "sensor"; anchor = "coap://spurious.example.com:5683"
            //    </ sensors / light >; ct = 41; rt - "light-lux"; if= "sensor"

        }

        public void PostTo()
        {
            CoapClient c = new CoapClient(Program.Host) {
                UriPath = "/.well-known/core",
                UriQuery = "ep=node1",
                Timeout = 5000,
                EndPoint = EndPoints.First()

            };

            Response r = c.Post(new byte[] { }, MediaType.ApplicationLinkFormat);
            if (r == null) {
                Console.WriteLine("No response received");
            }
            else {
                if (r.StatusCode != StatusCode.Changed) {
                    Console.WriteLine("Incorrect response");
                }

                Console.WriteLine(Utils.ToString(r));
            }
        }
    }

    class NopResource : Resource
    {
        public NopResource(string name) : base(name)
        {
            switch (name) {
                case "sensors":
                    Visible = false;
                    break;

                case "temp":
                    Attributes.AddContentType(41);
                    Attributes.AddInterfaceDescription("sensor");
                    Attributes.AddResourceType("temperature-c");
                    Attributes.Set("anchor", "coap://spurious.example.com:5683");
                    break;

                case "light":
                    Attributes.AddContentType(41);
                    Attributes.AddResourceType("light-lux");
                    Attributes.AddInterfaceDescription("sensor");
                    break;
            }
        }
    }


}
