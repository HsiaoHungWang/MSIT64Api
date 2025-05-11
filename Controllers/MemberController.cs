using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;
using MSIT64Api.Models;
using MSIT64Api.Models.DTO;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MSIT64Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MemberController : ControllerBase
    {
        private readonly MyDbContext _context;
        private readonly IConfiguration _configuration;
        public MemberController(IConfiguration configuration, MyDbContext context)
        {
            _configuration = configuration;
            _context = context;
        }

        [HttpGet("Protected")]
        public ActionResult Protected()
        {
            //取得Client送過來的JWT的資料
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            //驗證JWT的資料
            var validationResult = ValidateJwtToken(token);
            if (!validationResult.IsValid)
            {
                return Unauthorized(validationResult.Message);
            }
            else
            {
                return Ok(validationResult.Message);
            }


        }

        [HttpPost("Login")]
        public ActionResult GetLogin(LoginDTO loginDTO)
        {

            //假設登入驗證成功
            var memberExists = _context.Members.Any(m => m.Name == loginDTO.Name);
         
            if (memberExists)
            {
                //從appsettings.json讀取密鑰
                var secretKey = _configuration["JwtSettings:SecretKey"];
                if (string.IsNullOrEmpty(secretKey))
                {
                    return BadRequest("SecretKey not found.");
                }

                //建立一個處理 JWT 的工具，它可以用來產生或解析 token。
                var tokenHandler = new JwtSecurityTokenHandler();

                // 根據密鑰，建立對稱加密的金鑰（HMAC SHA-256）
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
                //設定簽章憑證（HMAC SHA256）
                //使用金鑰和 HMAC-SHA256 演算法來簽署 JWT，以防止被竄改。
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                
                //定義 JWT 的內容
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[] {
                        //new Claim("sub", email),
                        new Claim("name",loginDTO.Name),
                        new Claim("role", "admin")
                    }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    Issuer = _configuration["JwtSettings:Issuer"],
                    Audience = _configuration["JwtSettings:Audience"],
                    SigningCredentials = credentials
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);


                return Ok(new { Token = tokenHandler.WriteToken(token) });


            }

            //回應登入失敗
            return Unauthorized("Invalid username or password.");








            //return Ok();
        }


        private (bool IsValid, string Message) ValidateJwtToken(string token)
        {
            // 與簽名時使用的密鑰相同
            var secretKey = _configuration["JwtSettings:SecretKey"];
            if (secretKey == null)
            {
                return (false, $"Token SecretKey Missing");
            }
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _configuration["JwtSettings:Issuer"], // 與簽發時一致
                ValidAudience = _configuration["JwtSettings:Audience"], // 與簽發時一致
                IssuerSigningKey = key
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                // 驗證 JWT
                tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);

                // 如果令牌驗證成功
                return (true, "Token is valid.");
            }
            catch (SecurityTokenException ex)
            {
                // 如果令牌驗證失敗
                return (false, $"Token validation failed: {ex.Message}");
            }
            catch (Exception ex)
            {
                // 其他錯誤
                return (false, $"An error occurred: {ex.Message}");
            }
        }

    }
}
