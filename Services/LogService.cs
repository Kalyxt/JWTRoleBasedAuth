using JWTRoleBasedAuth.Data.Models.Logs;
using JWTRoleBasedAuth.Data;
using static JWTRoleBasedAuth.Base.RunTimeDataClasses.LogFeatures;

namespace JWTRoleBasedAuth.Services
{

    public class LogService(DataContext dataContext)
    {

        private readonly DataContext _DataContext = dataContext;

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

                await _DataContext.SysLogs.AddAsync(tmp_Log);
                await _DataContext.SaveChangesAsync();
                
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
