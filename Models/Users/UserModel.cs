namespace JWTRoleBasedAuth.Models.Users;

public class UserModel
{
    #region PROPERTIES


    public string? GUID { get; set; }


    public string? UserName { get; set; }


    public string? IdentificationNumber { get; set; }


    public DateTime ValidUntil { get; set; }


    public bool IsEnabled { get; set; }


    public bool IsEmailVerified { get; set; }

    public string DateFormatted
    {
        get
        {
            return ValidUntil.ToString("d");
        }
    }

    #endregion

}
