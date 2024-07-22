using JWTRoleBasedAuth.Data.Models.Users;
using JWTRoleBasedAuth.Data;
using JWTRoleBasedAuth.Models.Users;
using JWTRoleBasedAuth.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JWTRoleBasedAuth.Services;

public class UserService(DataContext dbContext,
                         LogService logService,
                         UserManager<UserDataModel> userManager)
{        
    private readonly DataContext _dbContext = dbContext;
    private readonly LogService _logService = logService;
    private readonly UserManager<UserDataModel> _userManager = userManager;

    #region PUBLIC METHODS

    /// <summary>
    /// Load user list.
    /// </summary>
    /// <returns></returns>
    public async Task<ResultModel<List<UserModel>>> GetUserList()
    {
        ResultModel<List<UserModel>> resultModel = new();

        try
        {
            List<UserDataModel> userDataList = await _dbContext.Users.ToListAsync();
            if (userDataList == null || userDataList.Count == 0)
            {
                resultModel.description = "User list is empty.";
                return resultModel;
            }

            // Convert to UserModel.
            List<UserModel> userList = new();
            foreach (UserDataModel userData in userDataList
                      ?? Enumerable.Empty<UserDataModel>())
            {
                UserModel userModel = new()
                {
                    GUID = userData.UserGUID,
                    IdentificationNumber = userData.IdentificationNumber,
                    UserName = userData.UserName,
                    IsEnabled = userData.IsEnabled,
                    IsEmailVerified = userData.EmailConfirmed,
                    ValidUntil = userData.ValidUntil
                };
                userList.Add(userModel);
            }

            // OK.
            resultModel.result = true;
            resultModel.data = userList;
        }
        catch (Exception ex)
        {
            resultModel.description = $"GetUserList - error while loading user list. '{ex.Message}' '{ex.InnerException?.Message}'";

            await _logService.LogEvent(u_enm_LogType: Base.RunTimeDataClasses.LogFeatures.enm_LogType.Users,
                                        u_Identifier: string.Empty,
                                        u_Message: resultModel.description);
        }

        return resultModel;
    }

    #endregion

}
