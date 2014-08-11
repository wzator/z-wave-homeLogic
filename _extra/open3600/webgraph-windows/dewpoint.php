<?php
/*  weathergraphs.php v 2.0 for ws3600
 *  Copyright 2004, Kenneth Lavrsen
 *  Copyright 2005, Grzegorz Wisniewski, Sander Eerkes
 *  This program is published under the GNU Public license
 */
include 'graph.php';

$fil=fopen("./log3600.log","r");
$i=0;
fseek ($fil, -30000, SEEK_END);
$streng = fgets($fil, 1000);
while (!feof($fil)) {
    $streng = fgets($fil, 1000);
    $components = preg_split("/[\s]/", $streng);
    if (IsSet($components[5]))
    {
        $time[$i]= $components[2];
        $date[$i]= $components[1];
        $value1[$i]= $components[5];
        $i++;
    }    
}
fclose($fil);

$numberof = count($time);
$start = $numberof - (36*6+6);

$line = new graph(640,400);
$line->parameter['label_font'] = 'arial.ttf';
$line->parameter['title'] = 'Dewpoint';
$line->parameter['x_label'] = 'Time';
$line->parameter['x_axis_text'] = 3;
$line->parameter['x_grid'] = 'none';
$line->parameter['y_label_left'] = 'deg C';
$line->parameter['y_min_left'] = -20;
$line->parameter['y_max_left'] = 30;
$line->parameter['y_decimal']= 0;
//$line->parameter['num_x_ticks'] = 7;
$line->parameter['y_axis_gridlines'] = 6;
$line->parameter['point_size'] = 6;
$line->parameter['shadow'] = 'none';

$i=$start;
while (substr($time[$i],3,2) != "00")
{
    $i++;
}
$start=$i;

for ($i=$start,$j=0 ; $i < $numberof ; $i++,$j++)
{
    $line->x_data[$j]= substr($time[$i],0,5);
    $line->y_data['Dp'][$j]= $value1[$i];
}

// format for each data set
$line->y_format['Dp'] = 
  array('colour' => 'red', 'line' => 'line', 'point' => 'dot');

// order in which to draw data sets.
$line->y_order = array('Dp');

// draw it.
$line->draw();



?>
