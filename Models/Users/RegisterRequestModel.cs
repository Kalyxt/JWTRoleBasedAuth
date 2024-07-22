namespace JWTRoleBasedAuth.Models.Users
{
    public class RegisterRequestModel
    {
        #region PROPERTIES


        public string? UserGUID { get; set; }

        public string? IdentificationNumber { get; set; }

        public string? Email { get; set; }

        #endregion
    }
}
