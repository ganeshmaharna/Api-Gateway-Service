class AppError extends Error{
    constructor(message, errorname,statusCode){
        super(message);
        this.statusCode=statusCode; 
        this.explanation=message;
        this.errorname=errorname;
    }
}
module.exports = AppError;