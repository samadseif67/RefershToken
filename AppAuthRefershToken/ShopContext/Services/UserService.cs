using System.Security.Claims;

namespace AppAuthRefershToken.ShopContext.Services
{
    public interface IUserService
    {
        string GetName();
    }


    public class UserService: IUserService
    {
        private readonly IHttpContextAccessor _contextAccessor;
        public UserService(IHttpContextAccessor contextAccessor)
        {

            _contextAccessor = contextAccessor; 
        }
        public string GetName()
        {
            var result = string.Empty;
            if(_contextAccessor.HttpContext is not null)
            {
                result= _contextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }
            return result;
        }


    }
}
