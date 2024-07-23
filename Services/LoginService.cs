using JWTRoleBasedAuth.Data.Models.Users;
using JWTRoleBasedAuth.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using JWTRoleBasedAuth.Base;
using JWTRoleBasedAuth.Models;
using System.Security.Claims;
using JWTRoleBasedAuth.Models.Users;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.EntityFrameworkCore;
using System;
using System.Data;

namespace JWTRoleBasedAuth.Services
{
    public class LoginService(DataContext dbContext,
                              LogService logService,
                              UserManager<UserDataModel> userManager,
                              SignInManager<UserDataModel> signInManager,
                              RoleManager<RoleDataModel> roleManager,
                              IConfiguration configuration)
    {
        private readonly DataContext _dbContext = dbContext;
        private readonly LogService _logService = logService;
        private readonly UserManager<UserDataModel> _userManager = userManager;
        private readonly SignInManager<UserDataModel> _signInManager = signInManager;
        private readonly RoleManager<RoleDataModel> _roleManager = roleManager;
        private readonly IConfiguration _configuration = configuration;

        #region PUBLIC METHODS

        /// <summary>
        /// User login.
        /// </summary>
        /// <param name="u_UserLogin"></param>
        /// <returns></returns>
        public async Task<ResultModel<string>> Login(UserLoginModel u_UserLogin)
        {
            ResultModel<string> resultModel = new();
            resultModel.result = false;

            try
            {
                // Create default users.
                resultModel = await this.CreateDefaultUsers();
                if (resultModel.result == false)
                {
                    resultModel.FromResultModel(resultModel);
                    return resultModel;
                }

                // Validations.
                if (string.IsNullOrEmpty(u_UserLogin.Email) == true)
                {
                    resultModel.data = "Wrong user credentials.";
                    resultModel.result = false;
                    return resultModel;
                }

                if (string.IsNullOrEmpty(u_UserLogin.Password) == true)
                {
                    resultModel.data = "Wrong user credentials.";
                    resultModel.result = false;
                    return resultModel;
                }

                var user = await this._userManager.FindByEmailAsync(u_UserLogin.Email);
                if (user != null)
                {
                    if (user.IsEnabled == false)
                    {
                        // User is deactivated.
                        resultModel.data = "User is deactivated.";
                        resultModel.result = false;
                        resultModel.errNumber = 7000;
                        return resultModel;
                    }

                    // Password check.
                    var signIn = await this._signInManager.CheckPasswordSignInAsync(user, u_UserLogin.Password, false);
                    if (signIn.Succeeded)
                    {
                        var userRoles = await _userManager.GetRolesAsync(user);

                        var authClaims = new List<Claim>
                        {
                            new(ClaimTypes.Name, user.UserName ?? ""),
                            new(ClaimTypes.Email, user.Email ?? ""),
                            new(ClaimTypes.Sid, user.Id.ToString()),
                        };

                        foreach (var userRole in userRoles)
                        {
                            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                            authClaims.Add(new Claim("roles", userRole));
                            authClaims.Add(new Claim(ClaimTypes.GroupSid, userRole));
                        }

                        string? JWTToken;
                        // Generate JWT token.
                        (resultModel, JWTToken) = await this.GenerateToken(authClaims);
                        if (resultModel.result == false)
                        {
                            return resultModel;
                        }

                        if (string.IsNullOrEmpty(JWTToken) == true)
                        {
                            resultModel.data = "Error while generating token.";
                            return resultModel;
                        }

                        // OK.
                        resultModel.result = true;
                        resultModel.data = JWTToken;
                        return resultModel;
                    }
                    else
                    {
                        // Wrong password.
                        resultModel.description = "Wrong password.";
                        resultModel.result = false;
                        return resultModel;
                    }
                }
                else
                {
                    resultModel.data = "User with this email doesn't exist.";
                    return resultModel;
                }
            }
            catch (Exception ex)
            {
                resultModel.description = string.Format($"Error while loggin in. '{ex.Message}' '{ex.InnerException?.Message}'");
                // Log error.
                await this._logService.LogEvent(u_enm_LogType: Base.RunTimeDataClasses.LogFeatures.enm_LogType.Users,
                                              u_Identifier: string.Empty,
                                              u_Message: $"{resultModel.description}");
            }

            return resultModel;
        }

        /// <summary>
        /// Register new user.
        /// </summary>
        /// <param name="u_RegisterRequest"></param>
        /// <returns></returns>
        public async Task<ResultModel<string>> Register(RegisterRequestModel u_RegisterRequest)
        {
            ResultModel<string> resultModel = new();

            try
            {
                // Validations.
                if (string.IsNullOrEmpty(u_RegisterRequest.UserGUID) == true)
                {
                    resultModel.description = "Invalid creadentials.";
                    resultModel.result = false;
                    return resultModel;
                }

                if (string.IsNullOrEmpty(u_RegisterRequest.IdentificationNumber) == true)
                {
                    resultModel.description = "Invalid creadentials.";
                    resultModel.result = false;
                    return resultModel;
                }

                if (string.IsNullOrEmpty(u_RegisterRequest.Email) == true)
                {
                    resultModel.description = "Invalid creadentials.";
                    resultModel.result = false;
                    return resultModel;
                }

                var userExists = await this.UserExists(u_RegisterRequest.UserGUID);
                if (userExists.data == true)
                {
                    resultModel.description = "User already exists.";
                    resultModel.result = false;
                    return resultModel;
                }

                UserDataModel tmp_UserDataModel = new UserDataModel
                {
                    UserGUID = u_RegisterRequest.UserGUID,
                    UserName = u_RegisterRequest.Email,
                    Email = u_RegisterRequest.Email,
                    CompanyEmail = u_RegisterRequest.Email,
                    IdentificationNumber = u_RegisterRequest.IdentificationNumber,
                    IsEnabled = true,
                    ValidUntil = DateTime.Now.AddDays(179)
                };

                // User create.
                var createUserResult = await this._userManager.CreateAsync(tmp_UserDataModel);
                if (createUserResult.Succeeded)
                {
                    var result_pass = await this.SetPassword(tmp_UserDataModel, "password123");
                    if (result_pass == false)
                    {
                        resultModel.description = "Error while creating user password.";
                        resultModel.result = false;
                        return resultModel;
                    }

                    // Add client role.
                    var clientRoleAdd = this._dbContext.Roles?.FirstOrDefault(role => role.Name == "Client");
                    if (clientRoleAdd != null)
                    {
                        var newClient = await _userManager.FindByEmailAsync(tmp_UserDataModel.Email);

                        if (newClient != null)
                        {
                            await _userManager.AddToRoleAsync(newClient, "Client");
                        }
                    }
                }
                else
                {
                    string tmp_Errors = string.Empty;

                    foreach (var error in createUserResult.Errors ??
                                Enumerable.Empty<IdentityError>())
                    {
                        // Catch errors.
                        tmp_Errors = tmp_Errors + ($"Error: {error.Code} - {error.Description}");
                    }

                    resultModel.description = "User not registered.";
                    resultModel.result = false;
                    return resultModel;
                }

                // OK.
                resultModel.result = true;
            }
            catch (Exception ex)
            {
                resultModel.description = string.Format($"Error while registering user. '{ex.Message}' '{ex.InnerException?.Message}'");
                // Log error.
                await this._logService.LogEvent(u_enm_LogType: Base.RunTimeDataClasses.LogFeatures.enm_LogType.Users,
                                              u_Identifier: string.Empty,
                                              u_Message: $"{resultModel.description}");
            }

            return resultModel;
        }


        public async Task<ResultModel<bool>> UserExists(string u_UserIdentificator)
        {
            ResultModel<bool> resultModel = new();

            try
            {
                if (string.IsNullOrEmpty(u_UserIdentificator) == true)
                {
                    resultModel.description = "GetUser - invalid creadentials.";
                    resultModel.result = false;
                    return resultModel;
                }

                var user = await this._dbContext.Users.FirstOrDefaultAsync(x => x.UserGUID == u_UserIdentificator);
                if (user != null)
                {
                    resultModel.data = true;
                }

                // OK.
                resultModel.result = true;
            }
            catch (Exception ex)
            {
                resultModel.description = string.Format($"Error while validating user existence. '{ex.Message}' '{ex.InnerException?.Message}'");
                // Log error.
                await this._logService.LogEvent(u_enm_LogType: Base.RunTimeDataClasses.LogFeatures.enm_LogType.Users,
                                          u_Identifier: string.Empty,
                                          u_Message: resultModel.description);
            }

            return resultModel;
        }

        /// <summary>
        /// Returns user with given identificator.
        /// </summary>
        /// <param name="u_UserIdentificator"></param>
        /// <returns></returns>
        public async Task<ResultModel<UserDataModel>> GetUser(string u_UserIdentificator)
        {
            ResultModel<UserDataModel> resultModel = new();

            try
            {
                // Validation.
                if (string.IsNullOrEmpty(u_UserIdentificator) == true)
                {
                    resultModel.description = "GetUser - invalid creadentials.";
                    resultModel.result = false;
                    return resultModel;
                }

                var user = await this._dbContext.Users.FirstOrDefaultAsync(x => x.UserGUID == u_UserIdentificator);
                if (user == null)
                {
                    resultModel.description = "GetUser - user not found.";
                    resultModel.result = false;
                    return resultModel;
                }

                // OK.
                resultModel.result = true;
                resultModel.data = user;
            }
            catch (Exception ex)
            {
                resultModel.description = string.Format($"Error while getting user. '{ex.Message}' '{ex.InnerException?.Message}'");
                // Zalogovať udalosť.
                await this._logService.LogEvent(u_enm_LogType: Base.RunTimeDataClasses.LogFeatures.enm_LogType.Users,
                                          u_Identifier: string.Empty,
                                          u_Message: resultModel.description);
            }

            return resultModel;
        }
        #endregion

        #region PRIVATE METHODS

        private async Task<(ResultModel<string>, string?)> GenerateToken(IEnumerable<Claim> claims)
        {
            ResultModel<string> myEx = new ResultModel<string>();

            try
            {
                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"] ?? string.Empty));

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Issuer = _configuration["Jwt:Issuer"],
                    Audience = _configuration["Jwt:Audience"],
                    Expires = DateTime.UtcNow.AddHours(24),
                    SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256),
                    Subject = new ClaimsIdentity(claims),
                    TokenType = "jwtAuthType",
                    Claims = new Dictionary<string, object>
                    {
                        { "roles", claims.FirstOrDefault(x => x.Type == "roles")?.Value },
                        { "role", claims.FirstOrDefault(x => x.Type == ClaimTypes.Role)?.Value }
                    }
                };

                var tokenHandler = new JwtSecurityTokenHandler();

                var token = tokenHandler.CreateToken(tokenDescriptor);
                var encodedToken = tokenHandler.WriteToken(token);

                await Task.Delay(0);

                // OK
                myEx.result = true;
                return (myEx, encodedToken);
            }
            catch (Exception ex)
            {
                myEx.data = string.Format($"Error while generating access token. '{ex.Message}'");
                return (myEx, null);
            }
        }

        /// <summary>
        /// Create default users.
        /// </summary>
        private async Task<ResultModel<string>> CreateDefaultUsers()
        {
            ResultModel<string> myEx = new ResultModel<string>();

            try
            {
                var user = await this._userManager.FindByEmailAsync("client@test.com");
                if (user == null)
                {
                    UserDataModel tmp_User = new()
                    {
                        UserName = "client@test.com",
                        Email = "client@test.com",
                        CompanyEmail = "client@test.com",
                        IdentificationNumber = "111111111",
                        UserGUID = Guid.NewGuid().ToString(),
                        IsEnabled = true,
                        ValidUntil = DateTime.Now.AddYears(30)
                    };

                    var result = await this._userManager.CreateAsync(tmp_User);
                    var result_pass = await this.SetPassword(tmp_User, "a+sdadssadasda12345asdasdadasd6789+");
                    bool roleExists = await _roleManager.RoleExistsAsync("Administrator");

                    if (!roleExists)
                    {
                        var administratoRole = new RoleDataModel
                        {
                            Name = "Administrator",
                            NormalizedName = "ADMINISTRATOR"
                        };
                        await _roleManager.CreateAsync(administratoRole);

                        var clientRole = new RoleDataModel
                        {
                            Name = "Client",
                            NormalizedName = "CLIENT"
                        };
                        await _roleManager.CreateAsync(clientRole);
                    }

                    // Add newly created user to client role.
                    var clientRoleAdd = this._dbContext.Roles?.FirstOrDefault(role => role.Name == "Client");
                    if (clientRoleAdd != null)
                    {
                        var client = await _userManager.FindByEmailAsync("client@test.com");

                        if (client != null)
                        {
                            await _userManager.AddToRolesAsync(client, new[] { "Client" });
                        }
                    }

                    // Admin.
                    tmp_User = new()
                    {
                        UserName = "dashboard@test.com",
                        Email = "dashboard@test.com",
                        CompanyEmail = "dashboard@test.com",
                        IdentificationNumber = "111111111",
                        UserGUID = Guid.NewGuid().ToString(),
                        IsEnabled = true,
                        ValidUntil = DateTime.Now.AddYears(30)
                    };

                    result = await this._userManager.CreateAsync(tmp_User);
                    result_pass = await this.SetPassword(tmp_User, "a+sdadssadasda12345asdasdadasd6789+");

                    var clientDashboard = await _userManager.FindByEmailAsync("dashboard@test.com");

                    if (clientDashboard != null)
                    {
                        await _userManager.AddToRolesAsync(clientDashboard, new[] { "Administrator" });
                    }
                }

                // OK.
                myEx.result = true;
            }
            catch (Exception ex)
            {
                myEx.data = string.Format($"Error while creating default users. '{ex.Message}' '{ex.InnerException?.Message}'");
                // Log event.
                await _logService.LogEvent(u_enm_LogType: Base.RunTimeDataClasses.LogFeatures.enm_LogType.Users,
                                          u_Identifier: "",
                                          u_Message: myEx.data);
            }

            return myEx;
        }

        /// <summary>
        /// Set user password.
        /// </summary>
        /// <param name="u_User"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        private async Task<bool> SetPassword(UserDataModel u_User, string newPassword)
        {
            try
            {
                // Generate a token to reset the password
                var token = await _userManager.GeneratePasswordResetTokenAsync(u_User);

                // Reset the password for the user
                var result = await _userManager.ResetPasswordAsync(u_User, token, newPassword);

                if (result.Succeeded)
                {
                    // Password updated successfully
                    return true;
                }
                else
                {
                    // Failed to update the password, handle the error
                    return false;
                }
            }
            catch (Exception ex)
            {
                await _logService.LogEvent(u_enm_LogType: Base.RunTimeDataClasses.LogFeatures.enm_LogType.Users,
                                          u_Identifier: "",
                                          u_Message: $"Error while setting up user password. '{ex.Message}' '{ex.InnerException?.Message}'");

                return false;
            }
        }

        #endregion

    }
}
