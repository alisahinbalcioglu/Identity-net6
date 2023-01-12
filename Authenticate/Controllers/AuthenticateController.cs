using Authenticate.Models;
using Authenticate.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Authenticate.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        private readonly IConfiguration _configuration;
        private readonly ITokenService _tokenService;
        private readonly ILoginService _loginService;
        private readonly ITenantService _tenantService;

        public AuthenticateController(IConfiguration configuration, ITokenService tokenService, ILoginService loginService,
            UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, ITenantService tenantService)
        {
            _userManager = userManager;
            _configuration = configuration;
            _tokenService = tokenService;
            _loginService = loginService;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _tenantService = tenantService;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                var userRoles = await _userManager.GetRolesAsync(user);
                TokenResponseModel tokenResponse = new TokenResponseModel()
                {
                    JWTToken = _tokenService.GetJWTToken(userRoles, user),
                    RefreshToken = _tokenService.GetRefreshToken(user)
                };
                return Ok(tokenResponse);
            }

            return Unauthorized();
        }


        [HttpPost]
        [Route("logout")]
        public async Task<IActionResult> LogOut([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if (user != null)
            {
                await _signInManager.SignOutAsync();
                return Ok();
            }

            return BadRequest();
        }

        [HttpPost]
        [Route("validate-tokens")]
        public async Task<IActionResult> ValidateTokens([FromBody] RefreshTokenRequest req)
        {
            string? jwt_token = req?.jwtToken;
            string? ref_token = req?.refreshToken;
            string? userName = req?.userName;

            TokenResponseModel tokenResponse = new TokenResponseModel();

#pragma warning disable CS8604 // Olası null başvuru bağımsız değişkeni.
            if (_tokenService.IsValidJWT(userName, jwt_token))
            {
#pragma warning disable CS8602 // Olası bir null başvurunun başvurma işlemi.
                var user = await _userManager.FindByNameAsync(req.userName);
#pragma warning restore CS8602 // Olası bir null başvurunun başvurma işlemi.
                var userRoles = await _userManager.GetRolesAsync(user);

                tokenResponse = new TokenResponseModel()
                {
                    JWTToken = new TokenModel() { Token = req.jwtToken, UserName = req.userName, is_expired = false },
                    RefreshToken = new TokenModel() { Token = req.refreshToken, UserName = req.userName, is_expired = false }
                };

            }
            else if (_tokenService.IsValidRefreshToken(userName, ref_token))
            {
#pragma warning disable CS8602 // Olası bir null başvurunun başvurma işlemi.
                var user = await _userManager.FindByNameAsync(req.userName);
#pragma warning restore CS8602 // Olası bir null başvurunun başvurma işlemi.
                var userRoles = await _userManager.GetRolesAsync(user);

                tokenResponse = new TokenResponseModel()
                {
                    JWTToken = _tokenService.GetJWTToken(userRoles, user),
                    RefreshToken = _tokenService.GetRefreshToken(user)
                };

            }
            else
            {
#pragma warning disable CS8602 // Olası bir null başvurunun başvurma işlemi.
                tokenResponse.RefreshToken.Token = "expired";
#pragma warning restore CS8602 // Olası bir null başvurunun başvurma işlemi.
#pragma warning disable CS8602 // Olası bir null başvurunun başvurma işlemi.
                tokenResponse.JWTToken.Token = "expired";
#pragma warning restore CS8602 // Olası bir null başvurunun başvurma işlemi.
            }
#pragma warning restore CS8604 // Olası null başvuru bağımsız değişkeni.

            return Ok(tokenResponse);
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest req)
        {
#pragma warning disable CS8604 // Olası null başvuru bağımsız değişkeni.
            if (_tokenService.IsValidJWT(req.userName, req.jwtToken))
            {
                if (_tokenService.IsValidRefreshToken(req.userName, req.refreshToken))
                {
                    var user = await _userManager.FindByNameAsync(req.userName);
                    var userRoles = await _userManager.GetRolesAsync(user);

                    TokenResponseModel tokenResponse = new TokenResponseModel()
                    {
                        JWTToken = _tokenService.GetJWTToken(userRoles, user),
                        RefreshToken = _tokenService.GetRefreshToken(user)
                    };
                    return Ok(tokenResponse);
                }

                return BadRequest("Invalid Refresh token");
            }
#pragma warning restore CS8604 // Olası null başvuru bağımsız değişkeni.
            return BadRequest("Invalid JWT");
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var res = await _loginService.RegisterUserAsync(model);

            if (res?.StatusCode == StatusCodes.Status200OK)
                return Ok(res);
            else
#pragma warning disable CS8629 // Boş değer atanabilir değer türü null olabilir.
                return StatusCode((int)res?.StatusCode, res.Object);
#pragma warning restore CS8629 // Boş değer atanabilir değer türü null olabilir.
        }

        [HttpPost]
        [Route("register-operator")]
        public async Task<IActionResult> RegisterOperator([FromBody] RegisterModel model)
        {
            var res = await _loginService.RegisterOperatorAsync(model);

            if (res?.StatusCode == StatusCodes.Status200OK)
                return Ok(res);
            else
#pragma warning disable CS8629 // Boş değer atanabilir değer türü null olabilir.
                return StatusCode((int)res?.StatusCode, res.Object);
#pragma warning restore CS8629 // Boş değer atanabilir değer türü null olabilir.
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var res = await _loginService.RegisterAdminAsync(model);

            if (res.StatusCode == StatusCodes.Status200OK)
                return Ok(res);

#pragma warning disable CS8629 // Boş değer atanabilir değer türü null olabilir.
            return StatusCode((int)res?.StatusCode, res.Message);
#pragma warning restore CS8629 // Boş değer atanabilir değer türü null olabilir.
        }

        [HttpPost]
        [Route("register-tenant")]
        public async Task<IActionResult> RegisterTenant([FromBody] RegisterTenantModel model)
        {
            var res = await _tenantService.AddNewTenantAsync(model);

            if (res?.StatusCode == StatusCodes.Status200OK)
                return Ok(res);
            else
#pragma warning disable CS8629 // Boş değer atanabilir değer türü null olabilir.
                return StatusCode((int)res?.StatusCode, res.Object);
#pragma warning restore CS8629 // Boş değer atanabilir değer türü null olabilir.

        }
    }
}
