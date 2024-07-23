using Microsoft.AspNetCore.Components.Authorization;
using System.Globalization;
using System.Security.Claims;
using System.Text.Json.Nodes;
using System.Text;
using System.Text.Json;
using JWTRoleBasedAuth.Models.Users;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.Net.Http.Headers;

namespace JWTRoleBasedAuth.Auth
{
    public class JwtAuthenticationStateProvider : AuthenticationStateProvider
    {

        private readonly ProtectedLocalStorage _localStorage;

        private static AuthenticationState NotAuthenticatedState = new AuthenticationState(new System.Security.Claims.ClaimsPrincipal());

        private AuthUser? _user;

        //private readonly HttpClient _httpClient;

        public JwtAuthenticationStateProvider(ProtectedLocalStorage localStorage)
        {
            _localStorage = localStorage;
            //_httpClient = httpClient;
        }

        /// <summary>
        /// The display name of the user.
        /// </summary>
        public string? Email => this._user?.Email;

        /// <summary>
        /// The role of the user.
        /// </summary>
        public string? Role => this._user?.Role;

        /// <summary>
        /// <see langword="true"/> if there is a user logged in, otherwise false.
        /// </summary>
        public bool IsLoggedIn => this._user != null;

        /// <summary>
        /// The current JWT token or <see langword="null"/> if there is no user authenticated.
        /// </summary>
        public string? Token => this._user?.Jwt;


        /// <summary>
        /// Loads information about the current user.
        /// </summary>
        /// <returns></returns>
        public async Task<AuthUser> GetUser()
        {
            try
            {
                var jwt = await _localStorage.GetAsync<string>("AccessToken");
                string token = jwt.Value ?? string.Empty;

                var principal = JwtSerialize.Deserialize(token);
                return new AuthUser(token, principal);
            }
            catch (Exception)
            {
                return new AuthUser("", new ClaimsPrincipal());
            }
        }

        /// <summary>
        /// Called when page loads.
        /// </summary>
        /// <returns></returns>
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            AuthenticationState tmp_AuthState = NotAuthenticatedState;

            try
            {
                var jwt = await _localStorage.GetAsync<string>("AccessToken");
                
                string token = jwt.Value ?? string.Empty;
                //_httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var principal = JwtSerialize.Deserialize(token);
                this._user = new AuthUser(token, principal);

                tmp_AuthState = new AuthenticationState(this._user.claimsPrincipal);

                return tmp_AuthState;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            return NotAuthenticatedState;
        }

        public void NotifyUserAuthentication(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                //var identity = new ClaimsIdentity(jwtToken.Claims, "jwtAuthType", nameType: "name", roleType: "roles");
                var identity = new ClaimsIdentity(jwtToken.Claims, "jwtAuthType");
                var user = new ClaimsPrincipal(identity);


                var authState = Task.FromResult(new AuthenticationState(user));
                NotifyAuthenticationStateChanged(authState);
            }
            catch (Exception)
            {

                throw;
            }

        }

        /// <summary>
        /// Logout the current user.
        /// </summary>
        public void Logout()
        {
            this._user = null;
            this.NotifyAuthenticationStateChanged(Task.FromResult(GetState()));
        }

        /// <summary>
        /// Constructs an authentication state.
        /// </summary>
        /// <returns>The created state.</returns>
        private AuthenticationState GetState()
        {
            if (this._user != null)
            {
                AuthenticationState tmp_AuthState = new AuthenticationState(this._user.claimsPrincipal);

                return tmp_AuthState;
            }
            else
            {
                return NotAuthenticatedState;
            }
        }

        public class JwtSerialize
        {
            public static ClaimsPrincipal Deserialize(string jwtToken)
            {
                ClaimsPrincipal principal = new ClaimsPrincipal();

                try
                {
                    JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

                    // Validate token format
                    if (!tokenHandler.CanReadToken(jwtToken))
                    {
                        throw new ArgumentException("Invalid token format");
                    }

                    // Read token claims
                    JwtSecurityToken jwtSecurityToken = tokenHandler.ReadJwtToken(jwtToken);

                    // Create ClaimsIdentity
                    ClaimsIdentity claimsIdentity = new ClaimsIdentity(jwtSecurityToken.Claims, "JwtAuth");

                    // Create ClaimsPrincipal
                    principal = new ClaimsPrincipal(claimsIdentity);

                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                
                return principal;
            }
        }
    }

}
