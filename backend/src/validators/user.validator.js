import Joi from "joi";

export const userSignupValidator = (data) => {
  const schema = Joi.object({
    email: Joi.string().email().required().label("email"),
    fullName: Joi.string().min(3).required().label("fullname"),
    password: Joi.string()
      .pattern(
        new RegExp(
          '^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()_+\\[\\]{}|;:",.<>?/]).{8,30}$'
        )
      )
      .required()
      .label("password"),
  }).messages({
    "string.empty": `Please enter a valid {#label}`,
    "string.pattern.base":
      "Password must be between 8 to 30 characters long and contain at least one uppercase letter, one lowercase letter, one number and one special character",
    "any.required": `{#label} is required`,
    "string.email": `Please enter a valid email address`,
  });
  return schema.validate(data, { errors: { wrap: { label: "" } } });
};
