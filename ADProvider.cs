using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Cryptography;

namespace adquery {
    public class AdUserProvider {  
            public AdUser CurrentUser {  
                get;  
                set;  
            }  
            public bool Initialized {  
                get;  
                set;  
            }  

            private Dictionary<string,string> groups {
                get;
            }
            public AdUserProvider(){
                groups = new Dictionary<string, string>();
            }
            public  PrincipalSearchResult<Principal> GetDomainUsers(string connectString) {    
                    PrincipalContext context = new PrincipalContext(ContextType.Domain, connectString);  
                    UserPrincipal principal = new UserPrincipal(context);  
                    principal.UserPrincipalName = "*@*";  
                    principal.Enabled = true;  
                    PrincipalSearcher searcher = new PrincipalSearcher(principal);  
                    PrincipalSearchResult<Principal> psr = searcher.FindAll();
                    principal.Dispose();
                    context.Dispose();
                    searcher.Dispose();
                    return psr;
                    //.Take(50).AsQueryable().Cast < UserPrincipal > ().FilterUsers().SelectAdUsers().OrderBy(x => x.Surname).ToList();  
                    
            
            }  
            public PrincipalSearchResult<Principal> FindDomainUsers(string server, string container, string userName, string pwd) {  
                    PrincipalContext context = new PrincipalContext(ContextType.Domain, server, container, userName, pwd);  
                    UserPrincipal principal = new UserPrincipal(context);  
                    //principal.SamAccountName =  "*{search}*";  
                    //principal.Enabled = true;  
                    PrincipalSearcher searcher = new PrincipalSearcher(principal);  
                    return searcher.FindAll();
                    //.AsQueryable().Cast < UserPrincipal > ().FilterUsers().SelectAdUsers().OrderBy(x => x.Surname).ToList();  
                    //return users;  
            }  

            public void directorySearch(string connectString){
                // create and return new LDAP connection with desired settings
                DirectoryEntry ldapConnection = new DirectoryEntry(connectString);
                //ldapConnection.Path = "LDAP://OU=Users, OU=automation,DC=autoldap,DC=local";
                ldapConnection.AuthenticationType = AuthenticationTypes.Secure;
                Console.WriteLine(ldapConnection.Username);
            }

            public List<AdUser> directorySearchUserNoPropFilter(string loginUser, string loginPwd, string domainName){
                DirectoryEntry entry = new DirectoryEntry(domainName, loginUser, loginPwd);
                //Console.Write(string.Format("Parameters for directory service: {0} {1} {2}", loginUser, loginPwd, domainName));
                DirectorySearcher directorysearch = new DirectorySearcher(entry);
                directorysearch.PageSize = 2000;
                directorysearch.SearchScope = SearchScope.Subtree;
                directorysearch.Filter = "(objectClass=User)";
                //Console.WriteLine(" ... . " , directorysearch.ToString()) ;
                SearchResultCollection items = directorysearch.FindAll();
                Console.WriteLine("Number of user with all properties: " + items.Count);
                List<AdUser> users = new List<AdUser>();
                foreach (SearchResult item in items)
                {

                    System.Byte [] sid = (System.Byte [])item.Properties["objectsid"][0];
                    int primaryGroupId = (int)item.Properties["primarygroupid"][0];
                    string primaryGroupName = "";
                    if ( sid != null | sid.Length > 0){
                            byte [] groupid = getGroupIDFromPrimaryGroupAndSID(primaryGroupId, sid);
                            string lookup = BitConverter.ToString(groupid).Replace("-","");

                            primaryGroupName = findGroupBySid ( lookup, false );
                    }    
                    AdUser user = new AdUser();

                    user.Name = item.Properties["name"][0].ToString();
                    //user.Surname = item.Properties["sn"][0].ToString();
                    user.GivenName = item.Properties["givenname"].ToString();
                    //user.Description = item.Properties["description"][0].ToString();
                    user.SamAccountName = item.Properties["samaccountname"][0].ToString();
                    //user.UserCannotChangePassword = bool.Parse(item.Properties["userAccountControl"][0].ToString());
                    //user.AccountExpirationDate = DateTime.FromFileTimeUtc(long.Parse(item.Properties["accountexpires"][0].ToString()));
                    var lastLogOn = DateTime.FromFileTime((long)item.Properties["lastLogon"][0]);
                    user.LastLogon = lastLogOn.ToString("o");
                    
                    user.UserPrincipalName = item.Properties["name"][0].ToString();
                    //user.ScriptPath = item.Properties["scriptpath"][0].ToString();
                    //user.HomeDrive = item.Properties["homedrive"][0].ToString();
                    //user.LastPasswordSet = DateTime.FromFileTimeUtc(long.Parse(item.Properties["pwdlastset"][0].ToString()));
                    user.DistinguishedName = item.Properties["distinguishedname"][0].ToString();
                    //user. = item.Properties["memberOf"].ToString();
                    user.Domain = primaryGroupName;
                    users.Add(user);
                }
                entry.Dispose();
                directorysearch.Dispose();
                return users;
        }

        public void directorySearchGroup(string loginUser, string loginPwd, string domainName, int printCnt, List<string> properties){
                DirectoryEntry entry = new DirectoryEntry(domainName, loginUser, loginPwd);
                //Console.Write(string.Format("Parameters for directory service: {0} {1} {2}", loginUser, loginPwd, domainName));
                DirectorySearcher directorysearch = new DirectorySearcher(entry);
                directorysearch.PageSize = 2000;
                directorysearch.SearchScope = SearchScope.Subtree;
                directorysearch.Filter = "(objectClass=group)";
                //Console.WriteLine(" ... . " , directorysearch.ToString()) ;
                SearchResultCollection items = directorysearch.FindAll();
                Console.WriteLine("Number of group with all properties: " + items.Count);
                int printOnce = printCnt;
                foreach (SearchResult item in items)
                {

                    //if(printOnce == 0) break;
                    //Console.WriteLine(item.Properties.Count);
                    foreach (string name in item.Properties.PropertyNames)
                    {
                        //Console.Write(string.Format("{0}: {1}, ",name,item.Properties[name][0].ToString()));
                        // if(properties.Contains(name)){
                        //     if("objectsid".Equals(name)){
                        //         byte[] ba = (byte[])item.Properties[name][0];
                        //         groups.Add(BitConverter.ToString(ba));
                        //         string objectValue = BitConverter.ToString(ba);
                        //         Console.Write(string.Format("Property Name: {0}: Value: {1}, ",name,objectValue));
                        //         //SecurityIdentifier sid = new SecurityIdentifier(ba);
                        //     } else {
                        //         Console.Write(string.Format("Property Name: {0}: Value: {1}, ",name,item.Properties[name][0].ToString()));
                        //     }
                        // }

                        byte[] ba = (byte[])item.Properties["objectsid"][0];
                        //string dn = item.Properties["distinguishedname"][0].ToString();
                        string dn = item.Properties["name"][0].ToString();
                        string key = BitConverter.ToString(ba).Replace("-","");
                        if ( !groups.ContainsKey(key) ){
                            Console.WriteLine(string.Format("Adding Key/value: {0}/{1}" , key, dn));
                            groups.Add(key, dn);
                        }
                        
                        //Console.WriteLine(name);
                    }
                    //--printOnce;
                    string str = item.Properties["name"][0].ToString();
                    //Console.Write(string.Format("Group name: {0}", str));
                }
                entry.Dispose();
        }
        public List<AdUser> directorySearchUserSelectedProps(string loginUser, string loginPwd, string domainName){
            var entry = new DirectoryEntry(domainName, loginUser, loginPwd);
            List<AdUser> users = new List<AdUser>();
            //Console.Write(string.Format("Parameters for directory service: {0} {1} {2}", loginUser, loginPwd, domainName));
            DirectorySearcher directorysearch = new DirectorySearcher(entry);
            directorysearch.PageSize = 2000;
            directorysearch.SearchScope = SearchScope.Subtree;
            //directorysearch.SearchScope = SearchScope.OneLevel;
            //directorysearch.Filter = "(objectClass=User)";
            //directorysearch.Filter = "(&(objectCategory=person)(objectClass=User)(!primaryGroupID=513))";
            directorysearch.Filter = "(&(objectCategory=person)(objectClass=user))";
            directorysearch.PropertiesToLoad.Add("name");
            directorysearch.PropertiesToLoad.Add("givenname");
            directorysearch.PropertiesToLoad.Add("sn");
            directorysearch.PropertiesToLoad.Add("description");
            directorysearch.PropertiesToLoad.Add("samaccountname");
            directorysearch.PropertiesToLoad.Add("userAccountControl");
            directorysearch.PropertiesToLoad.Add("accountexpires");
            directorysearch.PropertiesToLoad.Add("lastLogon");
            directorysearch.PropertiesToLoad.Add("profilePath");
            directorysearch.PropertiesToLoad.Add("scriptpath");
            directorysearch.PropertiesToLoad.Add("homedrive");
            directorysearch.PropertiesToLoad.Add("pwdlastset");
            directorysearch.PropertiesToLoad.Add("distinguishedname");
            directorysearch.PropertiesToLoad.Add("memberOf");
            directorysearch.PropertiesToLoad.Add("primarygroupid");
            directorysearch.PropertiesToLoad.Add("objectsid");
            
            //directorysearch.PropertiesToLoad.Add("memberof");
            

            //Console.WriteLine(" ... . " , directorysearch.ToString()) ;
            SearchResultCollection items = directorysearch.FindAll();
            Console.WriteLine("Number of user selected properties: " + items.Count);
         
            foreach (SearchResult item in items)
            {
                System.Byte [] sid = (System.Byte [])item.Properties["objectsid"][0];
                int primaryGroupId = (int)item.Properties["primarygroupid"][0];
                if ( sid != null | sid.Length > 0){
                        byte [] groupid = getGroupIDFromPrimaryGroupAndSID(primaryGroupId, sid);
                        string lookup = BitConverter.ToString(groupid).Replace("-","");

                    string primaryGroupName = findGroupBySid ( lookup, false );

                    AdUser user = new AdUser();

                     user.Name = item.Properties["name"][0].ToString();
                    //user.Surname = item.Properties["sn"][0].ToString();
                    user.GivenName = item.Properties["givenname"].ToString();
                    //user.Description = item.Properties["description"][0].ToString();
                    user.SamAccountName = item.Properties["samaccountname"][0].ToString();
                    //user.UserCannotChangePassword = bool.Parse(item.Properties["userAccountControl"][0].ToString());

                    var lastLogOn = DateTime.FromFileTime((long)item.Properties["lastLogon"][0]);
                    user.LastLogon = lastLogOn.ToString("o");

                    //user.AccountExpirationDate = DateTime.FromFileTimeUtc(long.Parse(item.Properties["accountexpires"][0].ToString()));
                    
                    user.AccountExpirationDate = item.Properties["accountexpires"][0].ToString();
                    

                    user.UserPrincipalName = item.Properties["name"][0].ToString();
                    //user.ScriptPath = item.Properties["scriptpath"][0].ToString();
                    //user.HomeDrive = item.Properties["homedrive"][0].ToString();
                    //user.LastPasswordSet = DateTime.FromFileTimeUtc(long.Parse(item.Properties["pwdlastset"][0].ToString()));
                    user.DistinguishedName = item.Properties["distinguishedname"][0].ToString();
                    //user. = item.Properties["memberOf"].ToString();
                    user.Domain = primaryGroupName;
                    users.Add(user);
            
                }    
                // foreach (string name in item.Properties.PropertyNames)
                // {
                //     if( oneTime < 4  && name.Contains("memberof"))
                //         Console.WriteLine(string.Format("Name: {0}: Value: {1}, ",name,item.Properties[name][0].ToString()));
                // }
                
            }
            entry.Dispose();
            directorysearch.Dispose();

            return users;
        }
        public void addUserPrincipals(string loginUser, string loginPwd, string domainName, string prefix, string groupDN, int howMany){
            PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, domainName, loginUser, loginPwd);
            
          for(int i = 0; i < howMany; i++){
                UserPrincipal UserPrincipal1 = new UserPrincipal(principalContext,prefix + "_" + i, GenerateToken(14), true);
        
                //User Logon Name
               
                UserPrincipal1.UserPrincipalName = prefix + "SamAccountName_" + i;
                UserPrincipal1.Name = prefix + "Name_" + i;
                UserPrincipal1.GivenName = prefix + "GivenName_" + i;
                UserPrincipal1.Surname = prefix + "SurName_" + i;
                UserPrincipal1.DisplayName = prefix + "DisplayNam_" +i;
                UserPrincipal1.Description = prefix + "Description_"+i;
                UserPrincipal1.Enabled = true;
            
                UserPrincipal1.Save();
            }
        }

         public static string GenerateToken(int length)
        {
            using (RNGCryptoServiceProvider cryptRNG = new RNGCryptoServiceProvider())
            {
                byte[] tokenBuffer = new byte[length];
                cryptRNG.GetBytes(tokenBuffer);
                return Convert.ToBase64String(tokenBuffer);
            }
        }

        public string GetPrimaryGroupName(string userSamAccountName, string connectString)

        {
            List<byte> domainSid = new List<byte>();
            List<byte> primaryGroupSid = new List<byte>();
            //byte[] primaryGroupSid
            int primaryGroupId;
            string primaryGroupOctet;
            string primaryGroupName;
            DirectoryEntry rootDse;
            DirectoryEntry domainRoot;
            DirectoryEntry primaryGroup;
            DirectorySearcher searcher;
            SearchResultCollection results;
            SearchResult result;
            IEnumerator enumerator;
            rootDse = new DirectoryEntry(connectString);
            domainRoot = new DirectoryEntry("LDAP://" + (rootDse.Properties["defaultNamingContext"].Value.ToString()));
            domainSid.Add((byte)domainRoot.Properties["objectSID"].Value);
            searcher = new DirectorySearcher(domainRoot);
            searcher.SearchScope = SearchScope.Subtree;
            searcher.CacheResults = false;
            searcher.PropertiesToLoad.AddRange(new string[] { "primaryGroupID" });
            searcher.Filter = String.Format("(&(objectCategory=user)(sAMAccountName={0}))", userSamAccountName);
            results = searcher.FindAll(); //'I don't use FindOne because it leaks memory if the search fails in 1.1 or lower...
            enumerator = results.GetEnumerator();
            if (enumerator.MoveNext())
            {
                result = (SearchResult)(enumerator.Current);
                primaryGroupId = (int)(result.Properties["primaryGroupId"][0]);
                
                //primaryGroupSid.(domainSid.Length + 3);
                byte[] temp = new byte[domainSid.Count + 3];
                if (primaryGroupSid != null)
                {
                    Array.Copy(primaryGroupSid.ToArray(), temp, Math.Min(primaryGroupSid.Count, temp.Length));
                    primaryGroupSid.AddRange( temp );
                }
                Array.Copy(domainSid.ToArray(), primaryGroupSid.ToArray(), domainSid.Count);
                Array.Copy(BitConverter.GetBytes(primaryGroupId), 0, primaryGroupSid.ToArray(), domainSid.Count, 4);
                primaryGroupSid[1] = Convert.ToByte((primaryGroupSid.Count - 8) / 4);
                primaryGroupOctet = ConvertToOctetString(primaryGroupSid, false, false);
                primaryGroup = new DirectoryEntry(String.Format("LDAP://<SID={0}>", primaryGroupOctet));
                primaryGroupName = primaryGroup.Properties["samAccountName"].Value.ToString();
                primaryGroup.Dispose();
            }
            else
            {
                primaryGroupName = String.Empty;

            }
            results.Dispose();
            searcher.Dispose();
            domainRoot.Dispose();
            rootDse.Dispose();
            return primaryGroupName;
        }

        public string ConvertToOctetString(List<byte> values, bool isAddBackslash, bool isUpperCase){
            int iterator;
            StringBuilder builder;
            string slash;
            if (isAddBackslash){
                slash = @"\";
            }
            else{
                slash = String.Empty;
            }
            string formatCode;
            if (isUpperCase){
                formatCode = "X2";
            }
            else{
                formatCode = "x2";
            }
            builder = new StringBuilder(values.Count * 2);
            for (iterator = 0; iterator <= values.Count - 1; iterator++){
                builder.Append(slash);
                builder.Append(values[iterator].ToString(formatCode));
            }

            return builder.ToString();

        }

        public byte[] getGroupIDFromPrimaryGroupAndSID(int primaryGroup, byte[] objectSid){
            int primaryGroupID = primaryGroup;
            System.Text.StringBuilder escapedGroupSid = new System.Text.StringBuilder();
            //Copy over everything but the last four bytes(sub-authority)
            //Doing so gives us the RID of the domain
            for(uint i = 0; i < objectSid.Length - 4; i++)
            {
                escapedGroupSid.AppendFormat("{0:x2}",objectSid[i]);
            }
            
            //Add the primaryGroupID to the escape string to build the SID of the primaryGroup
            for(uint i = 0; i < 4; i++)
            {
                escapedGroupSid.AppendFormat("{0:x2}",(primaryGroupID & 0xFF));
                primaryGroupID >>= 8;
            }
            
            
            //Console.WriteLine(string.Format("escaped: {0}: ", escapedGroupSid));
            //byte[] buffer = escapedGroupSid.ToString().Select(m => byte.Parse(m.ToString())).ToArray();
            //byte[] buffer = Array.ConvertAll<char,byte>(escapedGroupSid.ToString().ToCharArray(),c => Convert.ToByte(c.ToString()));
            String hex = escapedGroupSid.ToString();
            byte[] buffer = Enumerable.Range(0, hex.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                     .ToArray();
            
            return buffer;
        }
            // public Boolean initDC(){
            //     Forest adForest = Forest.GetCurrentForest();
            //     ActiveDirectorySite[] sites = new ActiveDirectorySite[adForest.Sites.Count];
            //     adForest.Sites.CopyTo(sites, 0);
            //     List<ActiveDirectorySubnet> subnets = new List<ActiveDirectorySubnet>();
            //     sites.ToList().ForEach(x =>
            //     {
            //         ActiveDirectorySubnet[] subnetTemp = new ActiveDirectorySubnet[x.Subnets.Count];
            //         x.Subnets.CopyTo(subnetTemp, 0);
            //         subnets.AddRange(subnetTemp);
            //     });
            //     IPAddress address = IPAddress.Parse("IPAddress to look up closest DC");
            //     var currentSubnet = subnets.Where(x => address.IsInRange(x.Name));
            //     var location = currentSubnet.First().Site.Name;

            //     DomainController dc = DomainController.FindOne(new DirectoryContext(DirectoryContextType.Domain, Domain), location);
            // }

        public string findGroupBySid(string sid, Boolean includeDomainUsers){
            string groupDN = "";
            try{
                    groupDN = groups[sid];
                    if(groupDN != null && (includeDomainUsers)?true:!groupDN.Contains("Domain Users")){
                        Console.WriteLine(string.Format("Primary group was found: {0}", groupDN));
                    }
                    
                }catch (KeyNotFoundException ignore){
                    //Console.WriteLine("Key = " + escapedGroupSid + " is not found.");
                }
            return groupDN;
        }
    }
    
}