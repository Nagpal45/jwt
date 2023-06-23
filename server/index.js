const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());


const users = [
    {
        id: 1,
        username: 'john',
        password: 'John0908',
        isAdmin: true
    },
    {
        id: 2,
        username: 'jane',
        password: 'Jane0908',
        isAdmin: false
    }
];

let refreshTokens = [];

app.post('/api/refresh', (req, res) => {
    const refreshToken = req.body.token;
    if (!refreshToken) {
        return res.status(401).json({ message: "You are not authenticated" });
    }
    if (!refreshTokens.includes(refreshToken)) {
        return res.status(403).json({ message: "Refresh token is not valid" });
    }
    jwt.verify(
        refreshToken,
        "refreshSecretkey",
        (err, user) => {
            err && console.log(err);
            refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

            const newAccessToken = generateAccessToken(user);
            const newRefreshToken = generateRefreshToken(user);

            refreshTokens.push(newRefreshToken);

            res.status(200).json({ 
                accesstoken: newAccessToken,
                refreshToken: newRefreshToken
            });

        }
    )

}
)

const generateAccessToken = (user) => {
    const accesstoken = jwt.sign({
        id: user.id,
        isAdmin: user.isAdmin
    },"secretkey",
    {expiresIn:"5m"});
    return accesstoken;
}

const generateRefreshToken = (user) => {
    const refreshToken = jwt.sign({
        id: user.id,
        isAdmin: user.isAdmin
    },"refreshSecretkey",
    {expiresIn:"5m"});
    return refreshToken;
}

app.post('/api/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const user = users.find(u => u.username === username && u.password === password);
    if (user) {
        const accesstoken = generateAccessToken(user);
        const refreshToken =generateRefreshToken(user);

        refreshTokens.push(refreshToken);

    
        res.json({
            username: user.username,
            isAdmin: user.isAdmin,
            accesstoken,
            refreshToken
        })

    } else {
        res.status(400).send({ message: 'Invalid username or password' });
    }
});



const verify=(req,res,next)=>{
    const authHeader = req.headers.authorization;
    
    if(authHeader){
        const token = authHeader.split(' ')[1];
        
        jwt.verify(token, "secretkey", (err, user) => {
            if (err) {
                return res.status(403).json({message:"Token is not valid"});
            }
            req.user = user;
            next();
        }
        );
    }
    else{
        res.status(401).json({message:"You are not authenticated"})
    }
}

app.delete('/api/users/:userId',verify,(req,res)=>{
    if(req.user.id===parseInt(req.params.userId || req.user.isAdmin)){
        res.status(200).json({message:"User has been deleted"})
    }
    else{
        res.status(403).json({message:"You are not allowed to delete this user"})
    }
}
)

app.post('/api/logout', (req, res) => {
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    res.status(200).json({ message: "You logged out successfully" });
}
)



app.listen(5000, () => {
    console.log('server is listening on port 5000');
    }
);