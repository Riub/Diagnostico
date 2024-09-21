from turtle import *
import colorsys
import math
import random

speed(0.01)
bgcolor("black")

# Función para dibujar una flor
def draw_flower(posx, posy):
    penup()
    goto(posx, posy)
    pendown()
    
    for i in range(16):
        for j in range(18):
            c = colorsys.hsv_to_rgb(0.125, 1, 1)
            color(c)
            rt(90)
            circle(150 - j * 6, 90)
            lt(90)
            circle(150 - j * 6, 90)
            rt(180)
        circle(40, 24)

    # Dibuja el centro de la flor
    color("orange")
    fillcolor("orange")
    begin_fill()
    circle(40)  # Tamaño del centro
    end_fill()

# Función para dibujar el tallo con una hoja
def draw_stem_with_leaf(x, y):
    penup()
    goto(x, y)
    pendown()
    pos_leaf_y = y - 150  # Ajusta la posición de la hoja
    
    # Dibuja el tallo recto más largo
    color("green")
    pensize(12)
    setheading(270)
    fd(150)  # Longitud del tallo

    # Dibuja la hoja
    penup()
    goto(x, pos_leaf_y)
    pendown()
    pensize(2)
    begin_fill()
    setheading(135)
    circle(50, 90)
    setheading(45)
    circle(50, 90)
    end_fill()
    
    # Restaura el color y el grosor del lápiz
    penup()
    pensize(1)
    color("black")

# Función para generar estrellitas de forma aleatoria
def draw_random_stars(amount):
    for _ in range(amount):
        penup()
        x = random.randint(-400, 400)
        y = random.randint(-400, 400)
        goto(x, y)
        pendown()
        star_color = colorsys.hsv_to_rgb(random.random(), 1, 1)
        color(star_color)
        begin_fill()
        for _ in range(5):
            forward(11)
            right(144)
        end_fill()

# MAIN
# Dibujar el tallo
draw_stem_with_leaf(0, 0)  # Cambia la posición inicial del tallo

# Dibujar la flor
goto(0, 50)
setheading(0)
draw_flower(0, 50)

# Escribir el mensaje
hideturtle()
penup()
goto(0, 350)
pendown()
color("white")  # Cambia el color a blanco 
write("Para la niña más bonita", align="center", font=("Arial", 11, "normal"))

penup()
goto(0, -300)
pendown()
write("Mi loquita <3", align="center", font=("Arial", 11, "normal"))
hideturtle()

# Dibuja las estrellas aleatorias
draw_random_stars(50)

done()
