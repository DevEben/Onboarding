const joi = require('@hapi/joi');

const validateUser = (data) => {
    try {
        const validateSchema = joi.object({
            firstName: joi.string().min(3).max(30).trim().required().messages({
                'string.empty': "First name field can't be left empty",
                'string.min': "Minimum of 3 characters for the first name field",
                'any.required': "Please first name is required"
            }),
            lastName: joi.string().min(3).max(30).trim().required().messages({
                'string.empty': "Last name field can't be left empty",
                'string.min': "Minimum of 3 characters for the last name field",
                'any.required': "Please last name is required"
            }),
            userName: joi.string().min(3).max(30).trim().required().messages({
                'string.empty': "Username field can't be left empty",
                'string.min': "Minimum of 3 characters for the username field",
                'any.required': "Please username is required"
            }),
            phoneNumber: joi.string().min(11).max(11).trim().regex(/^0\d{10}$/).required().messages({
                'string.empty': "Phone number field can't be left empty",
                'string.min': "Phone number must be atleast 11 digit long e.g: 08123456789",
                'any.required': "Please phone number is required"
            }),
            email: joi.string().max(40).trim().email( {tlds: {allow: false} } ).required().messages({
                'string.empty': "Email field can't be left empty",
                'any.required': "Please Email is required"
            }),
            password: joi.string().min(8).max(20).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$')).trim().required().messages({
                'string.empty': "Password field can't be left empty",
                'string.pattern.base': 'Password must contain Lowercase, Uppercase, Numbers, and special characters',
                'string.min': "Password must be at least 8 characters long",
                'any.required': "Please password field is required"
            }),
        })
        return validateSchema.validate(data);
    } catch (err) {
        return res.status(500).json({
            Error: "Error while validating user: " + err.message,
        })
    }
}


const validateUserLogin = (data) => {
    try {
        const validateSchema = joi.object({
            email: joi.string().max(40).trim().email( {tlds: {allow: false} } ).required().messages({
                'string.empty': "Email field can't be left empty",
                'any.required': "Please Email is required"
            }),
            password: joi.string().min(8).max(20).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$')).trim().required().messages({
                'string.empty': "Password field can't be left empty",
                'string.pattern.base': 'Password must contain Lowercase, Uppercase, Numbers, and special characters',
                'string.min': "Password must be at least 8 characters long",
                'any.required': "Please password field is required"
            }),
        })
        return validateSchema.validate(data);
    } catch (err) {
        return res.status(500).json({
            Error: "Error while validating user: " + err.message,
        })
    }
}



module.exports = {
    validateUser,
    validateUserLogin,

}