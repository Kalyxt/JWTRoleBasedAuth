namespace JWTRoleBasedAuth.Base.RunTimeDataClasses
{
    public class BaseFeatures
    {

        public BaseFeatures(JWTRoleBasedAuth.Base.AppEngine u_AppEngine)
        {
            this._appEngine = u_AppEngine;
        }

        #region FIELDS

        public JWTRoleBasedAuth.Base.AppEngine _appEngine;

        #endregion

        #region PROTECTED

        protected string getClassName()
        {
            return this.GetType().UnderlyingSystemType.Name;
        }

        #endregion

    }
}
