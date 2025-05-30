import random
import string


def generate_random_int(max_value: int = 100):
    """Generate Random Integer value between specified maximum value
    note: maximum_value is not consider in range"""
    return random.randint(0, max_value)


def generate_phone_number():
    """Generate Random 10 digit phone number starting with 72"""
    return "72" + "".join(random.choice(string.digits) for _ in range(8))


def generate_random_chars(length):
    """Generate a random string of given length containing characters only."""
    characters = string.ascii_letters
    return "".join(random.choice(characters) for _ in range(length))


def generate_random_char_digits(length):
    """Generate a random string of given length containing characters and digits only."""
    characters = string.ascii_letters + string.digits
    return "".join(random.choice(characters) for _ in range(length))


def generate_random_string(length):
    """Generate a random string of given length."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(characters) for _ in range(length))


def fuzz_string_type(var_name: str):
    var_name_lower = str(var_name).lower()
    if "email" in var_name_lower:
        var_value = generate_random_char_digits(6).lower() + "@example.com"
    elif "password" in var_name_lower:
        var_value = generate_random_string(15)
    elif "phone" in var_name_lower:
        var_value = generate_phone_number()
    elif "name" in var_name_lower:
        var_value = generate_random_chars(7)
    elif "username" in var_name_lower:
        var_value = generate_random_char_digits(6)
    else:
        var_value = generate_random_string(10)

    return var_value


def fill_schema_params(
    params: dict[dict], param_in: str = None, is_required: bool = None
):
    schema_params = []
    for var_name, var_data in params.items():
        var_type = var_data.get("type")

        match var_type:
            case "string":
                var_value = fuzz_string_type(var_name)

            case "integer":
                var_value = generate_random_int()

            case _:
                var_value = generate_random_string(10)

        var_data["value"] = var_value
        var_data["name"] = var_name

        if is_required:
            var_data["required"] = is_required

        if param_in:
            var_data["in"] = param_in

        schema_params.append(var_data)

    return schema_params


def fuzz_type_value(param_type: str, param_name: str):
    match param_type:
        case "string":
            param_value = fuzz_string_type(param_name)

        case "integer":
            param_value = generate_random_int()

        # TODO: handle file and array type

        case _:  # default case
            param_value = generate_random_string(10)

    return param_value


def fill_params(params: list[dict], is_v3: bool) -> list[dict]:
    """fills params for OAS/swagger specs"""
    schema_params = []
    for index, _ in enumerate(params):
        param_type = (
            params[index].get("schema", {}).get("type")
            if is_v3
            else params[index].get("type")
        )
        param_is_required = params[index].get("required")
        param_in = params[index].get("in")
        param_name = params[index].get("name", "")

        param_value = fuzz_type_value(param_type=param_type, param_name=param_name)

        if params[index].get("schema"):
            schema_type = params[index].get("schema", {}).get("type")
            if schema_type == "object":
                schema_obj = params[index].get("schema", {}).get("properties", {})
                filled_schema_params = fill_schema_params(
                    schema_obj, param_in, param_is_required
                )
            else:
                filled_schema_params = [
                    {
                        "in": param_in,
                        "name": param_name,
                        "required": param_is_required,
                        "value": param_value,
                        "type": param_type
                    }
                ]

            schema_params.append(filled_schema_params)
        else:
            params[index]["value"] = param_value

    # delete schema params
    for param in params:
        if param.get("schema"):
            params.remove(param)

    for schema_param in schema_params:
        params += schema_param

    return params
