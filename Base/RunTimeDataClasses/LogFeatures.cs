using JWTRoleBasedAuth.Data;
using JWTRoleBasedAuth.Data.Models.Logs;

namespace JWTRoleBasedAuth.Base.RunTimeDataClasses
{

    public class LogFeatures : BaseFeatures,
                               IDisposable
    {

        #region ENUMS

        /// <summary>
        /// Log type.
        /// </summary>
        public enum enm_LogType : int
        {
            /// <summary>
            /// Logs.
            /// </summary>
            Logs = 10,

            Info = 3000,

            /// <summary>
            /// Users.
            /// </summary>
            Users = 100,
        }

        #endregion

        public LogFeatures(JWTRoleBasedAuth.Base.AppEngine u_AppEngine) : base(u_AppEngine)
        {

        }

        #region METHODS

        public async Task LogEvent(enm_LogType u_enm_LogType,
                                   string? u_Identifier,
                                   string u_Message)
        {
            try
            {
                LogDataModel tmp_Log = new()
                {
                    RecordGUID = Guid.NewGuid().ToByteArray(),
                    DateTimeCreate = DateTime.Now,
                    LogType = (int)u_enm_LogType,
                    Identifier = u_Identifier ?? string.Empty,
                    Message = u_Message,
                };

                using (var scope = this._appEngine?.ServiceProvider.CreateScope())
                {
                    var dbContext = scope?.ServiceProvider.GetRequiredService<DataContext>();

                    if (dbContext == null)
                    {
                        return;
                    }

                    await dbContext.SysLogs.AddAsync(tmp_Log);
                    await dbContext.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        #endregion

        #region IDisposable

        private bool disposedValue;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                }

                try
                {

                }
                catch (Exception)
                {
                }


                disposedValue = true;
            }
        }


        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
