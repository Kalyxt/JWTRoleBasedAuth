
namespace JWTRoleBasedAuth.Base
{
    public class AppEngine : IDisposable
	{
        #region CONSTANTS

        /// <summary>
        /// App name.
        /// </summary>
        public const string CONST_APPNAME = "JWTRoleBasedAuthAPI";

        /// <summary>
        /// Release date.
        /// </summary>
        public const string CONST_APP_VERSION_DATE = "17.7.2024";

        /// <summary>
        /// API version.
        /// </summary>
        public static Version CONST_APP_APIVERSION = new Version(1, 0, 0);

        #endregion

        #region FIELDS

        public readonly IServiceProvider ServiceProvider;

        public bool LogFunctionCalls = true;

        #endregion

        #region CONSTRUCTOR

        public AppEngine(IServiceProvider serviceProvider)
		{

            this.ServiceProvider = serviceProvider;
            this.prp_RunTimeData = new RunTimeData(this);
		}

        #endregion

        #region PROPERTIES

        private JWTRoleBasedAuth.Base.RunTimeData prp_RunTimeData;
        public JWTRoleBasedAuth.Base.RunTimeData RunTimeData
        {
            get
            {
                return prp_RunTimeData;
            }
        }

        #endregion

        #region METHODS

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

