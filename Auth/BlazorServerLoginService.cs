using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.AspNetCore.Components;
using System.Security.Claims;
using System.Security.Cryptography;
using JWTRoleBasedAuth.Models;
using Microsoft.AspNetCore.Components.Authorization;
using Newtonsoft.Json.Linq;

namespace JWTRoleBasedAuth.Auth
{
    public class BlazorServerLoginService
    {
        private const string AccessToken = nameof(AccessToken);
        private const string RefreshToken = nameof(RefreshToken);

        private readonly ProtectedLocalStorage _localStorage;
        private readonly NavigationManager _navigation;
        private readonly JWTRoleBasedAuth.Services.LoginService _loginService;
        private readonly JwtAuthenticationStateProvider _authenticationStateProvider;
        public BlazorServerLoginService(ProtectedLocalStorage localStorage, 
                                        NavigationManager navigation,
                                        JWTRoleBasedAuth.Services.LoginService loginService,
                                        JwtAuthenticationStateProvider authenticationStateProvider)
        {
            _localStorage = localStorage;
            _navigation = navigation;
            _loginService = loginService;
            _authenticationStateProvider = authenticationStateProvider;
        }

        /// <summary>
        /// User login, saving jwt token to local storage.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        public async Task<ResultModel<string>> LoginAsync(JWTRoleBasedAuth.Models.Users.UserLoginModel model)
        {
            ResultModel<string> resultModel = new();

            try
            {
                resultModel = await _loginService.Login(model);
                if (string.IsNullOrEmpty(resultModel.data))
                    return resultModel;

                await _localStorage.SetAsync(AccessToken, resultModel.data);

                _authenticationStateProvider.NotifyUserAuthentication(resultModel.data);
                return resultModel;
            }
            catch (Exception)
            {
                return resultModel;
            }
        }


        public async Task<string> GetTokenAsync()
        {
            var emptyResult = new List<Claim>();
            ProtectedBrowserStorageResult<string> accessToken;


            try
            {
                accessToken = await _localStorage.GetAsync<string>(AccessToken);
            }
            catch (CryptographicException)
            {
                await LogoutAsync();
                return string.Empty;
            }

            return accessToken.Value ?? string.Empty;
        }

        public async Task LogoutAsync()
        {
            await RemoveAuthDataFromStorageAsync();
            _navigation.NavigateTo("/", true);
        }

        private async Task RemoveAuthDataFromStorageAsync()
        {
            await _localStorage.DeleteAsync(AccessToken);
            await _localStorage.DeleteAsync(RefreshToken);
        }
    }
}
