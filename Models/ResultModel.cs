using System;
using Microsoft.AspNetCore.Mvc;

namespace JWTRoleBasedAuth.Models
{
    public class ResultModel<T>
    {

        public ResultModel()
        {
            this.result = false;
            this.isWarning = false;
            this.description = string.Empty;
            this.data = default(T);
        }

        #region PROPERTIES

        public bool result { get; set; }

        public int errNumber { get; set; }

        public string? description { get; set; }

        public bool isWarning { get; set; }

        public T? data { get; set; }

        #endregion

        internal void FromResultModel<X>(ResultModel<X> resultModel)
        {
            this.result = resultModel.result;
            this.isWarning = resultModel.isWarning;
            this.errNumber = resultModel.errNumber;
            this.description = resultModel.description;
        }
    }
}

