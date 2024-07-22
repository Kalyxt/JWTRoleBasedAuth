using System.Text;

namespace JWTRoleBasedAuth.Models.Logs
{

    public class LogModel
    {

        #region PROPERTIES


        public DateTime DateTimeCreate { get; set; }

        public int LogType { get; set; }


        public string? Identifier { get; set; }

        public string? Message { get; set; }

        #endregion

        #region METHODS


        internal void FromLogDataModel(JWTRoleBasedAuth.Data.Models.Logs.LogDataModel u_LogDataModel)
        {
            try
            {
                this.DateTimeCreate = u_LogDataModel.DateTimeCreate;
                this.LogType = u_LogDataModel.LogType;
                this.Identifier = u_LogDataModel.Identifier;
                this.Message = u_LogDataModel.Message;

                // OK
            }
            catch (Exception ex)
            {
                throw new Exception("LogModel.FromLogDataModel", ex);
            }
        }


        #endregion
    }
}
