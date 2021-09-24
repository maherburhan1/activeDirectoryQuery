using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Diagnostics;


namespace adquery
{
    class Program
    {
        static void Main(string[] args)
        {
            if(args.Length > 0 ){
                Console.WriteLine("args: {0}", args);
            }
            // format for ldap url
            //LDAP://172.1.1.10:389/OU=USERS,DC=OZKARYDEV,DC=COM
            string domainName = "autoldap.local";
            string domainPart = "autolap";
            String domainStr = "CN=Users,DC=autolap,DC=local";
            string domainLDAP = "LDAP://(DC=autoldap, DC=local)";
            string domainLdapWithIP = "LDAP://10.220.50.127/CN=Users,DC=autoldap,DC=local";
            string domainLdapWithIPPrimaryGroup = "LDAP://10.220.50.127/(&(objectCategory=person)(objectClass=user)(DC=autoldap,DC=local)(!primaryGroupID=513))";
            string domainLdapWithIPNoLDAP = "10.220.50.127";
            string serverIP = "10.220.50.127";
            string loginUser = "domainu";
            string loginPwd = "P@ssword";
            var results = new List<SearchResult>();

            //addUserPrincipals(loginUser, loginPwd, domainLdapWithIPNoLDAP, 2000);
            // 10.220.50.127
            //string connectString = "LDAP://10.220.50.127/OU=Users,OU=automation,DC=autoldap,DC=local";
            //DirectoryEntry entry = new DirectoryEntry("10.220.50.127", loginUser, loginPwd);


            string container = "CN=Users,DC=autoldap,DC=local";

            AdUserProvider userProv = new AdUserProvider();

            // Add group to the cache (dictionary object)
            List<string> props = new List<string>();
            props.AddRange(new [] {"samaccountname", "objectsid"});
            Console.WriteLine("Caching domain groups...hit anykey to continue");
            Console.ReadLine();
            userProv.directorySearchGroup(loginUser, loginPwd, domainLdapWithIP,1, props);

             Console.WriteLine("Fetching domain users using principal search...hit anykey to continue");
            Console.ReadLine();
            Stopwatch stopWatchPrincipal = new Stopwatch();
            stopWatchPrincipal.Start();
            PrincipalSearchResult<Principal> domainUsers = userProv.FindDomainUsers(serverIP,container, loginUser, loginPwd);
            Console.WriteLine("Number of user with all properties: {0}", domainUsers.Count());
            
            stopWatchPrincipal.Stop();
            Console.WriteLine(string.Format("Time elapsed for principal search: {0} MS", stopWatchPrincipal.ElapsedMilliseconds));

            Console.WriteLine("Fetching domain users using directory search without filtering properties (all properties)...hit anykey to continue");
            Console.ReadLine();
            Stopwatch stopWatch = new Stopwatch();
            stopWatch.Start();
        
            userProv.directorySearchUserNoPropFilter(loginUser, loginPwd, domainLdapWithIP);
            stopWatch.Stop();

            long first = stopWatch.ElapsedMilliseconds;
            Console.WriteLine(string.Format("Time elapsed for directory search all properties: {0} MS",  first));
            

            Console.WriteLine("Fetching domain users using directory search with filtering properties (selected properties)...hit anykey to continue");
            Console.ReadLine();
            Stopwatch stopWatch2 = new Stopwatch();
            
            stopWatch2.Start();
            userProv.directorySearchUserSelectedProps (loginUser, loginPwd, domainLdapWithIP);
            stopWatch2.Stop();
            long second = stopWatch2.ElapsedMilliseconds;

            Console.WriteLine(string.Format("Time elapsed for directory search selected properties: {0} MS", second));

            Console.WriteLine(string.Format("Time saved fetching selected properties: {0}", (first - second)));

            

        }
       
        public static void addUsers(string loginUser, string loginPwd, string domainName, int howMany){
            DirectoryEntry entry = new DirectoryEntry(domainName, loginUser, loginPwd);

            for (int i = 0; i < howMany; i++)
            {
                try
                {
                    DirectoryEntry childEntry = entry.Children.Add("CN=TestUser" + i,  "user");
                    childEntry.CommitChanges();
                    entry.CommitChanges();
                    childEntry.Invoke("SetPassword", new object[] { "password" });
                    childEntry.CommitChanges();
                }
                catch (Exception ex)
                {

                }
            }
        }
    }
}
