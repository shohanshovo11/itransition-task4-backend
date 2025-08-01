using backend.Data;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IJwtService _jwtService;

        public UsersController(ApplicationDbContext context, IJwtService jwtService)
        {
            _context = context;
            _jwtService = jwtService;
        }

        // POST: api/users/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User model)
        {
            if (await _context.Users.AnyAsync(u => u.Email == model.Email))
                return BadRequest("Email is already registered.");

            model.PasswordHash = HashPassword(model.PasswordHash);
            model.LastLoginAt = DateTime.UtcNow;
            model.CreatedAt = DateTime.UtcNow;

            _context.Users.Add(model);
            await _context.SaveChangesAsync();

            var token = _jwtService.GenerateToken(model);

            return Ok(new LoginResponse
            {
                Token = token,
            });
        }

        // POST: api/users/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest model)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == model.Email);

            if (user == null || !VerifyPassword(model.Password, user.PasswordHash))
                return Unauthorized("Invalid email or password.");

            if (user.IsBlocked || user.IsDeleted)
                return Unauthorized("User is blocked or deleted.");

            // Generate JWT token
            var token = _jwtService.GenerateToken(user);

            // Update last login time
            user.LastLoginAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            return Ok(new LoginResponse
            {
                Token = token,
                User = user
            });
        }

        // GET: api/users
        [Authorize]
        [backend.Filters.NotBlocked]
        [HttpGet]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _context.Users
                .Where(u => !u.IsDeleted)
                .OrderByDescending(u => u.LastLoginAt)
                .Select(u => new
                {
                    u.Id,
                    u.Name,
                    u.Email,
                    u.LastLoginAt,
                    u.IsBlocked
                })
                .ToListAsync();

            return Ok(users);
        }

        // PUT: api/users/block
        [Authorize]
        [backend.Filters.NotBlocked]
        [HttpPut("block")]
        public async Task<IActionResult> BlockUsers([FromBody] Guid[] userIds)
        {
            var users = await _context.Users.Where(u => userIds.Contains(u.Id)).ToListAsync();

            foreach (var user in users)
            {
                user.IsBlocked = true;
            }

            await _context.SaveChangesAsync();
            return Ok("Selected users blocked.");
        }

        // PUT: api/users/unblock
        [Authorize]
        [backend.Filters.NotBlocked]
        [HttpPut("unblock")]
        public async Task<IActionResult> UnblockUsers([FromBody] Guid[] userIds)
        {
            var users = await _context.Users.Where(u => userIds.Contains(u.Id)).ToListAsync();

            foreach (var user in users)
            {
                user.IsBlocked = false;
            }

            await _context.SaveChangesAsync();
            return Ok("Selected users unblocked.");
        }

        // DELETE: api/users/delete
        [Authorize]
        [backend.Filters.NotBlocked]
        [HttpDelete("delete")]
        public async Task<IActionResult> DeleteUsers([FromBody] Guid[] userIds)
        {
            var users = await _context.Users.Where(u => userIds.Contains(u.Id)).ToListAsync();

            foreach (var user in users)
            {
                user.IsDeleted = true;
            }

            await _context.SaveChangesAsync();
            return Ok("Selected users deleted.");
        }

        // GET: api/users/check-status
        [Authorize]
        [backend.Filters.NotBlocked]
        [HttpGet("check-status")]
        public async Task<IActionResult> CheckStatus([FromQuery] Guid userId)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null || user.IsBlocked || user.IsDeleted)
                return Unauthorized("User is no longer valid.");

            return Ok("User is valid.");
        }

        // Utility Methods
        private static string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            var hashed = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(hashed);
        }

        private static bool VerifyPassword(string password, string hash)
        {
            return HashPassword(password) == hash;
        }
    }

    // Login DTO
    public class LoginRequest
    {
        public string Email { get; set; } = "";
        public string Password { get; set; } = "";
    }
}
