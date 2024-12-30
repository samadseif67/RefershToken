using AppAuthRefershToken.ShopContext.Dto;
using AppAuthRefershToken.ShopContext.Entites;
using AppAuthRefershToken.ShopContext.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AppAuthRefershToken.Controllers
{
    [Authorize]
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        private readonly IUserService _UserService;
        public AuthController(IConfiguration _configuration, IUserService UserService)
        {
            this._configuration = _configuration;
            this._UserService = UserService;
        }



        [HttpPost]
        public ActionResult GetMyName()
        {
            return Ok(_UserService.GetName());
        }

        [AllowAnonymous]
        [HttpPost]
        public ActionResult Register(UserDto userDto)
        {

            string Pass = userDto.Password;
            Pass = BCrypt.Net.BCrypt.HashPassword(Pass);

            user.Username = userDto.Username;
            user.PasswordHash = Pass;

            return Ok(user);
        }


        [AllowAnonymous]
        [HttpPost]
        public ActionResult Login(UserDto userDto)
        {
              
            if (user.Username != userDto.Username)
            {
                return BadRequest("user not found");
            }

            if (!BCrypt.Net.BCrypt.Verify(userDto.Password, user.PasswordHash))
            {
                return BadRequest("Wrong password");
            }

            string Token = CreateToken(user);

            var refershToken = GenerateRefershToken();
            SetRefershToken(refershToken);

            return Ok(Token);
        }


        [AllowAnonymous]
        [HttpPost]
        public async Task<ActionResult> GetRefershToken()
        {

            var refershToken = Request.Cookies["refershToken"];
            if (user.TokenExpire < DateTime.Now)
            {
                return Unauthorized("Token is Expire");
            }
            if (!user.RefershToken.Equals(refershToken))
            {
                return Unauthorized("Refresh Token Not Valid");
            }

            var token = CreateToken(user);
            var newRefershToken = GenerateRefershToken();
            SetRefershToken(newRefershToken);

            return Ok(token);

        }



        [NonAction]
        private string CreateToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
            new Claim(ClaimTypes.Name, user.Username),           
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Aud, _configuration["Jwt:Audience"]),
            new Claim(JwtRegisteredClaimNames.Iss, _configuration["Jwt:Issuer"])
        };

            var token = new JwtSecurityToken(
                issuer: _configuration["Issuer"],
                audience: _configuration["Audience"],
                claims: claims,
                expires: DateTime.Now.AddMonths(2),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
         

        [NonAction]
        private RefershToken GenerateRefershToken()
        {
            var refershToken = new RefershToken()
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expire = DateTime.Now.AddDays(7),
            };
            return refershToken;
        }

        [NonAction]
        private void SetRefershToken(RefershToken newRefershToken)
        {
            var cookiOption = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefershToken.Expire,

            };
            Response.Cookies.Append("refershToken", newRefershToken.Token, cookiOption);
            user.RefershToken = newRefershToken.Token;
            user.TokenCreate = newRefershToken.Create;
            user.TokenExpire = newRefershToken.Expire;
        }
         

    }
}
