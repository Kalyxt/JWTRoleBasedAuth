using Microsoft.Extensions.Diagnostics.HealthChecks;
using System.ComponentModel.DataAnnotations;

namespace JWTRoleBasedAuth.Models.Users
{
    public class UserLoginModel
    {

        public UserLoginModel(string email, string password)
        {
            this.Email = email;
            this.Password = password;
        }

        #region PROPERTIES

        public string Email { get; set; }

        public string Password { get; set; }


        #endregion

    }
}
