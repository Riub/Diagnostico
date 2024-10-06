import turtle
import math
import colorsys
import random

turtle.bgcolor("black")
turtle.pencolor("black")  
turtle.shape("triangle")
turtle.speed(0)


phi = 137.508 * (math.pi / 180)

def draw_flower(radius):
    for i in range(16):
        angle = i * (360 / 16) 
        turtle.penup()
        turtle.goto(radius * math.cos(math.radians(angle)), radius * math.sin(math.radians(angle)))  
        turtle.setheading(angle + 90)  
        turtle.pendown()

        for j in range(18):
            c = colorsys.hsv_to_rgb(0.125, 1, 1)
            turtle.color(c)
            turtle.right(90)
            turtle.circle(150 - j * 6, 90)
            turtle.left(90)
            turtle.circle(150 - j * 6, 90)
            turtle.right(180)
        turtle.circle(40, 24)

def draw_stem_with_leaf(x, y):
    turtle.penup()
    turtle.goto(x, y)
    turtle.pendown()
    pos_leaf_y = y - 200 

    turtle.color("green")
    turtle.pensize(12)
    turtle.setheading(270)
    turtle.forward(200)  
    
    turtle.right(45)  
    turtle.begin_fill()
    turtle.circle(50, 90)  
    turtle.right(90)
    turtle.circle(50, 90)  
    turtle.end_fill()
    turtle.left(135)  

def draw_small_heart(x, y):
    turtle.penup()
    turtle.goto(x, y)
    turtle.pendown()
    turtle.color("red") 
    turtle.begin_fill()
    turtle.left(140)
    turtle.forward(10) 
    turtle.circle(-5, 200)
    turtle.left(120)
    turtle.circle(-5, 200)
    turtle.forward(10)
    turtle.end_fill()
    turtle.setheading(0) 
def draw_random_small_hearts(amount):
    for _ in range(amount):
        x = random.randint(-400, 400)
        y = random.randint(-200, 400)
        draw_small_heart(x, y)
def draw_star(x, y):
    turtle.penup()
    turtle.goto(x, y)
    turtle.pendown()
    star_color = colorsys.hsv_to_rgb(random.random(), 1, 1)
    turtle.color(star_color)
    turtle.begin_fill()
    for _ in range(5):
        turtle.forward(15)
        turtle.right(144)
    turtle.end_fill()
    turtle.setheading(0)

def stamp_random_stars(amount):
    for _ in range(amount):
        x = random.randint(-400, 400)
        y = random.randint(-200, 400)
        draw_star(x, y) 

draw_stem_with_leaf(0, 0)  
turtle.pencolor("black")  
turtle.pensize(1)  

center_radius = math.sqrt(159) * 3  
draw_flower(center_radius)

turtle.fillcolor("#F38919") 
turtle.pencolor("black")  
turtle.begin_fill()

for i in range(160):
    r = math.sqrt(i) * 3  
    theta = i * phi 
    x = r * math.cos(theta)  
    y = r * math.sin(theta)  
    
    turtle.penup()
    turtle.goto(x, y) 
    turtle.setheading(math.degrees(theta)) 
    turtle.pendown()
    turtle.stamp() 
turtle.end_fill()

turtle.hideturtle()
turtle.penup()
turtle.goto(0, 350)
turtle.pendown()
turtle.color("white") 
turtle.write("Para mi princesa hermosa", align="center", font=("Dancing Script", 11, "normal"))
turtle.penup()
turtle.goto(0, -300)
turtle.pendown()
turtle.write("Te amo como las vacas", align="center", font=("Dancing Script", 11, "normal"))


turtle.penup()
turtle.goto(0, -320) 
turtle.pendown()
turtle.write("Muuuuuuuuucho <3", align="center", font=("Dancing Script", 11, "normal"))

draw_random_small_hearts(50)  
stamp_random_stars(50)   

turtle.done()
