namespace JWTRoleBasedAuth.Models.Users
{
    /// <summary>
    /// Info about logged in user.
    /// </summary>
    public class AuthUser
    {

        public AuthUser(string jwt, System.Security.Claims.ClaimsPrincipal claimsPrincipal)
        {
            this.Jwt = jwt;
            this.claimsPrincipal = claimsPrincipal;

            Initialize();
        }

        public string Role { get; set; }
        public string Email { get; set; }
        public string Jwt { get; set; }
        public System.Security.Claims.ClaimsPrincipal claimsPrincipal { get; set; }

        private void Initialize()
        {
            try
            {
                // search list of claims and get email and role.
                foreach (var claim in claimsPrincipal.Claims)
                {
                    if (claim.Type == "email")
                    {
                        this.Email = claim.Value;
                    }
                    else if (claim.Type == "roles")
                    {
                        this.Role = claim.Value;
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }


    }
}
