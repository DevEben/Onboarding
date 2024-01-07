const resetHTML = (userId) => {

    return `
    
    <!DOCTYPE html>
<html lang="en">
<head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Reset</title>
        </head>
        <body>
            <h1>Password Reset</h1>
            <form id="resetForm" action="/api/v1/reset-user/${userId}" method="post" enctype="application/x-www-form-urlencoded">
                <label for="password">New Password:</label>
                <input type="password" id="password" name="password" required>
                <button type="submit">Submit</button>
            </form>
</body>
</html>

    `
}

module.exports = resetHTML;