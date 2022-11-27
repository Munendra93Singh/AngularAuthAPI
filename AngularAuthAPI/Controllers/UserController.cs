using AngularAuthAPI.Context;
using AngularAuthAPI.Helper;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.RegularExpressions;
using System;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Diagnostics;

namespace AngularAuthAPI.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class UserController : ControllerBase
  { private readonly AppDbContext _authContext;
    public UserController(AppDbContext appDbContext)
    {
      _authContext = appDbContext;
    }
    [HttpPost("authenticate")]
    public async Task<IActionResult> Authenticate([FromBody] User userObj)
    {
      if (userObj == null)
        return BadRequest();

      var user = await _authContext.Users.
        //FirstOrDefaultAsync(x => x.Username == userObj.Username && x.Password == userObj.Password);
      FirstOrDefaultAsync(x => x.Username == userObj.Username );


      if (user == null)
        return NotFound(new {Message= "User Not Found!"});


      if (!PasswordHased.varifyPassword(userObj.Password, user.Password))
      {
        return BadRequest(new { Message = "Password is Incorrect" });
      }

      user.Token = CreateJwt(user); 

      return Ok(new
      {
        Token = user.Token,
        Message= "Login Success!"
      });
    }
    [HttpPost("register")]
    public async Task<IActionResult> RegisterUser([FromBody] User userObj)
    {
      if (userObj == null)
        return BadRequest();
      //Check Unique username---Start
      if(await CheckUserNameExistAsync(userObj.Username))
      {
        return BadRequest(new {Message ="username already Exist"});
      }
      //Check Unique Email---Start
      if (await CheckEmailExistAsync(userObj.Email))
      {
        return BadRequest(new { Message = "Email already Exist" });
      }
      //Check Unique Password-Stregth--Start
      var pass = CheckPasswordStength(userObj.Password);
      if (!string.IsNullOrEmpty(pass))
        return BadRequest(new { Message = pass.ToString() });
    
      //-----Hash Password-Start------
      userObj.Password = PasswordHased.HashPassword(userObj.Password);
      userObj.Role = "User";
      userObj.Token = "";
      //-------Hash Password End---------------
      await _authContext.Users.AddAsync(userObj);
      await _authContext.SaveChangesAsync();
      return Ok(new
      {
        Message ="User Registered!"
      });
    }
    private Task<bool>CheckUserNameExistAsync(string username)
        => _authContext.Users.AnyAsync(x => x.Username == username);

    private Task<bool> CheckEmailExistAsync(string email)
        => _authContext.Users.AnyAsync(x => x.Email == email);

    private string CheckPasswordStength(string password)
    {
      StringBuilder sb = new StringBuilder();
      if(password.Length < 9)
        sb.Append("Minimum password length should be 9"+Environment.NewLine);
        if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]")
          && Regex.IsMatch(password, "[0-9]")))
      sb.Append("Password should be Alphanumeric" + Environment.NewLine);
      if (!Regex.IsMatch(password, "[<,>,@,!,#,$,*,(,),_,+,-,[,\\],{,},?,:,;,|,',/,~,`,=]"))
        sb.Append("Password should contain special chars" + Environment.NewLine);
      return sb.ToString();
     
    }
    private string CreateJwt(User user)
    {
      var jwtTokenHandler = new JwtSecurityTokenHandler();
      var key = Encoding.ASCII.GetBytes ("veryverysecret.....");
      var identity = new ClaimsIdentity(new Claim[]
      {
        new Claim(ClaimTypes.Role, user.Role),
        new Claim(ClaimTypes.Name,$"{user.FirstName}{user.LastName}")
      });
      var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

      var tokenDescripter = new SecurityTokenDescriptor
      {
        Subject = identity,
        Expires = DateTime.Now.AddSeconds(10),
        SigningCredentials = credentials
      };
      var token =jwtTokenHandler.CreateToken(tokenDescripter);
      return jwtTokenHandler.WriteToken(token);
    }
    //[Authorize]
    [HttpGet]
    public async Task<ActionResult<User>>GetAllUsers()
    {
      return Ok(await _authContext.Users.ToListAsync());
    }
  }
}
