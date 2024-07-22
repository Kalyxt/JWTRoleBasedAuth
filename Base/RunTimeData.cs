using System;
using System.Collections.Concurrent;

namespace JWTRoleBasedAuth.Base
{

    public class RunTimeData : IDisposable
	{
		public RunTimeData(AppEngine appEngine)
		{

            this.prp_AppEngine = appEngine;

            this.prp_LogFeatures = new RunTimeDataClasses.LogFeatures(this.prp_AppEngine);

		}

        #region PROPERTIES

        private AppEngine prp_AppEngine;

        public AppEngine AppEngine
        {
            get
            {
                return prp_AppEngine;
            }
        }

        private JWTRoleBasedAuth.Base.RunTimeDataClasses.LogFeatures prp_LogFeatures;

        public JWTRoleBasedAuth.Base.RunTimeDataClasses.LogFeatures LogFeatures
        {
            get
            {
                return prp_LogFeatures;
            }
        }

        #endregion

        #region PRIVATE METHODS

        #endregion

        #region IDisposable

        private bool disposedValue;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                try
                {
                    if (disposing)
                    {
                        if (this.prp_LogFeatures != null)
                        {
                            this.prp_LogFeatures.Dispose();
                        }
                    }
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

