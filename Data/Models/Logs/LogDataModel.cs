using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.SqlTypes;

namespace JWTRoleBasedAuth.Data.Models.Logs
{

    [Table("sys_logs")]
    public class LogDataModel
    {

        #region PROPERTIES


        [NotMapped]
        public SqlBinary RecordGUID { get; set; }


        [Key]
        [Required]
        [MaxLength(16)]
        public byte[] RecordGUIDBytes
        {
            get => RecordGUID.Value;
            set => RecordGUID = new SqlBinary(value);
        }


        [Required]
        public DateTime DateTimeCreate { get; set; }

        [Required]
        public int LogType { get; set; }

        [Required]
        public string? Identifier { get; set; }

        public string? Message { get; set; }

        #endregion

    }
}
