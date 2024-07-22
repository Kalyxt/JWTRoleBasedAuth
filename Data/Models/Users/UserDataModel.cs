using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.SqlTypes;

namespace JWTRoleBasedAuth.Data.Models.Users
{
    public class UserDataModel : IdentityUser<long>
    {

        #region PROPERTIES

        public string? UserGUID { get; set; }

        public string? IdentificationNumber { get; set; }

        public string? CompanyEmail { get; set; }

        public DateTime ValidUntil { get; set; }

        public bool IsEnabled { get; set; }

        #endregion

    }
}
